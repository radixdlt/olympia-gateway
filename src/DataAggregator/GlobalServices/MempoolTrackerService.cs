/* Copyright 2021 Radix Publishing Ltd incorporated in Jersey (Channel Islands).
 *
 * Licensed under the Radix License, Version 1.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at:
 *
 * radixfoundation.org/licenses/LICENSE-v1
 *
 * The Licensor hereby grants permission for the Canonical version of the Work to be
 * published, distributed and used under or by reference to the Licensor’s trademark
 * Radix ® and use of any unregistered trade names, logos or get-up.
 *
 * The Licensor provides the Work (and each Contributor provides its Contributions) on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied,
 * including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT,
 * MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Whilst the Work is capable of being deployed, used and adopted (instantiated) to create
 * a distributed ledger it is your responsibility to test and validate the code, together
 * with all logic and performance of that code under all foreseeable scenarios.
 *
 * The Licensor does not make or purport to make and hereby excludes liability for all
 * and any representation, warranty or undertaking in any form whatsoever, whether express
 * or implied, to any entity or person, including any representation, warranty or
 * undertaking, as to the functionality security use, value or other characteristics of
 * any distributed ledger nor in respect the functioning or value of any tokens which may
 * be created stored or transferred using the Work. The Licensor does not warrant that the
 * Work or any use of the Work complies with any law or regulation in any territory where
 * it may be implemented or used or that it will be appropriate for any specific purpose.
 *
 * Neither the licensor nor any current or former employees, officers, directors, partners,
 * trustees, representatives, agents, advisors, contractors, or volunteers of the Licensor
 * shall be liable for any direct or indirect, special, incidental, consequential or other
 * losses of any kind, in tort, contract or otherwise (including but not limited to loss
 * of revenue, income or profits, or loss of use or data, or loss of reputation, or loss
 * of any economic or other opportunity of whatsoever nature or howsoever arising), arising
 * out of or in connection with (without limitation of any use, misuse, of any ledger system
 * or use made or its functionality or any performance or operation of any code or protocol
 * caused by bugs or programming or logic errors or otherwise);
 *
 * A. any offer, purchase, holding, use, sale, exchange or transmission of any
 * cryptographic keys, tokens or assets created, exchanged, stored or arising from any
 * interaction with the Work;
 *
 * B. any failure in a transmission or loss of any token or assets keys or other digital
 * artefacts due to errors in transmission;
 *
 * C. bugs, hacks, logic errors or faults in the Work or any communication;
 *
 * D. system software or apparatus including but not limited to losses caused by errors
 * in holding or transmitting tokens by any third-party;
 *
 * E. breaches or failure of security including hacker attacks, loss or disclosure of
 * password, loss of private key, unauthorised use or misuse of such passwords or keys;
 *
 * F. any losses including loss of anticipated savings or other benefits resulting from
 * use of the Work or any changes to the Work (however implemented).
 *
 * You are solely responsible for; testing, validating and evaluation of all operation
 * logic, functionality, security and appropriateness of using the Work for any commercial
 * or non-commercial purpose and for any reproduction or redistribution by You of the
 * Work. You assume all risks associated with Your use of the Work and the exercise of
 * permissions under this License.
 */

using Common.CoreCommunications;
using Common.Database.Models.Mempool;
using Common.Extensions;
using Common.Utilities;
using DataAggregator.Configuration;
using DataAggregator.DependencyInjection;
using Humanizer;
using Microsoft.EntityFrameworkCore;
using NodaTime;
using Prometheus;
using System.Collections.Concurrent;

using Core = RadixCoreApi.Generated.Model;

namespace DataAggregator.GlobalServices;

public record TransactionData(byte[] Id, Instant SeenAt, byte[] Payload, Core.Transaction Transaction);

public record NodeMempoolContents
{
    public Dictionary<byte[], TransactionData> Transactions { get; }

    public Instant AtTime { get; }

    public NodeMempoolContents(Dictionary<byte[], TransactionData> transactions)
    {
        Transactions = transactions;
        AtTime = SystemClock.Instance.GetCurrentInstant();
    }
}

public interface IMempoolTrackerService
{
    void RegisterNodeMempool(string nodeName, NodeMempoolContents nodeMempoolContents);

    Task HandleMempoolChanges(CancellationToken token);
}

public class MempoolTrackerService : IMempoolTrackerService
{
    private static readonly LogLimiter _combineMempoolsInfoLogLimiter = new(TimeSpan.FromSeconds(10), LogLevel.Information, LogLevel.Debug);

    private static readonly Gauge _combinedMempoolCurrentSizeTotal = Metrics
        .CreateGauge(
            "ng_node_mempool_combined_current_size_total",
            "Number of transactions seen currently in any node mempool."
        );

    private static readonly Counter _dbTransactionsAddedDueToNodeMempoolAppearanceCount = Metrics
        .CreateCounter(
            "ng_db_mempool_transactions_added_from_node_mempool_count",
            "Number of mempool transactions added to the DB due to appearing in a node mempool"
        );

    private static readonly Counter _dbTransactionsMarkedAsMissingCount = Metrics
        .CreateCounter(
            "ng_db_mempool_transactions_marked_as_missing_count",
            "Number of mempool transactions in the DB marked as missing"
        );

    private static readonly Counter _dbTransactionsReappearedCount = Metrics
        .CreateCounter(
            "ng_db_mempool_transactions_reappeared_count",
            "Number of mempool transactions in the DB which were marked as missing but now appear in a mempool again"
        );

    private static readonly Counter _dbTransactionsMarkedAsFailedForTimeoutCount = Metrics
        .CreateCounter(
            "ng_db_mempool_transactions_marked_as_failed_for_timeout_count",
            "Number of mempool transactions in the DB marked as failed due to timeout as they won't be resubmitted"
        );

    private readonly IDbContextFactory<AggregatorDbContext> _dbContextFactory;
    private readonly IAggregatorConfiguration _aggregatorConfiguration;
    private readonly IActionInferrer _actionInferrer;
    private readonly ILogger<MempoolTrackerService> _logger;
    private readonly ConcurrentDictionary<string, NodeMempoolContents> _latestMempoolContentsByNode = new();

    public MempoolTrackerService(
        IDbContextFactory<AggregatorDbContext> dbContextFactory,
        IAggregatorConfiguration aggregatorConfiguration,
        IActionInferrer actionInferrer,
        ILogger<MempoolTrackerService> logger
    )
    {
        _dbContextFactory = dbContextFactory;
        _aggregatorConfiguration = aggregatorConfiguration;
        _actionInferrer = actionInferrer;
        _logger = logger;
    }

    public void RegisterNodeMempool(string nodeName, NodeMempoolContents nodeMempoolContents)
    {
        _latestMempoolContentsByNode[nodeName] = nodeMempoolContents;
    }

    public async Task HandleMempoolChanges(CancellationToken token)
    {
        var combinedMempool = CombineNodeMempools();

        await EnsureDbMempoolTransactionsCreatedOrMarkedReappeared(combinedMempool, token);
        await HandleMissingPendingTransactions(combinedMempool.Keys.ToHashSet(), token);
    }

    private Dictionary<byte[], TransactionData> CombineNodeMempools()
    {
        var lastUpdatedToBeConsidered = Duration.FromSeconds(15);

        var nodeMempoolsToConsider = _latestMempoolContentsByNode
            .Where(kvp => kvp.Value.AtTime.WithinPeriodOfNow(lastUpdatedToBeConsidered))
            .ToList();

        if (nodeMempoolsToConsider.Count == 0)
        {
            throw new Exception(
                $"Don't have any recent mempool data from nodes within {lastUpdatedToBeConsidered.FormatSecondsHumanReadable()}"
            );
        }

        var combinedMempool = new Dictionary<byte[], TransactionData>(ByteArrayEqualityComparer.Default);

        foreach (var (_, mempoolContents) in nodeMempoolsToConsider)
        {
            foreach (var (identifier, data) in mempoolContents.Transactions)
            {
                if (!combinedMempool.ContainsKey(identifier))
                {
                    combinedMempool[identifier] = data;
                }
                else if (data.SeenAt > combinedMempool[identifier].SeenAt)
                {
                    combinedMempool[identifier] = data;
                }
            }
        }

        _logger.Log(
            _combineMempoolsInfoLogLimiter.GetLogLevel(),
            "There are {MempoolSize} transactions across node mempools: {NodesUsed}",
            combinedMempool.Count,
            nodeMempoolsToConsider.Select(kvp => kvp.Key).Humanize()
        );
        _combinedMempoolCurrentSizeTotal.Set(combinedMempool.Count);

        return combinedMempool;
    }

    private async Task EnsureDbMempoolTransactionsCreatedOrMarkedReappeared(
        Dictionary<byte[], TransactionData> combinedMempool,
        CancellationToken token
    )
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(token);

        IParsedTransactionMapper parsedTransactionMapper = new ParsedTransactionMapper<AggregatorDbContext>(dbContext, _actionInferrer);

        var mempoolTransactionIds = combinedMempool.Keys.ToList(); // Npgsql optimizes List<> Contains

        var existingDbTransactionsInANodeMempool = await dbContext.MempoolTransactions
            .Where(mt => mempoolTransactionIds.Contains(mt.TransactionIdentifierHash))
            .ToListAsync(token);

        var existingTransactionIds = existingDbTransactionsInANodeMempool
            .Select(et => et.TransactionIdentifierHash)
            .ToHashSet(ByteArrayEqualityComparer.Default);

        var newTransactions = combinedMempool.Values
            .Where(mt => !existingTransactionIds.Contains(mt.Id))
            .ToList();

        var gatewayTransactionDetails = await parsedTransactionMapper.MapToGatewayTransactionContents(
            newTransactions.Select(nt => nt.Transaction).ToList(),
            token
        );

        var newDbMempoolTransactions = newTransactions
            .Select((transactionData, index) => MempoolTransaction.NewFirstSeenInMempool(
                transactionData.Id,
                transactionData.Payload,
                gatewayTransactionDetails[index],
                transactionData.SeenAt
            ));

        _dbTransactionsAddedDueToNodeMempoolAppearanceCount.Inc(newTransactions.Count);

        dbContext.MempoolTransactions
            .AddRange(newDbMempoolTransactions);

        var reappearedTransactions = existingDbTransactionsInANodeMempool
            .Where(mt => mt.Status == MempoolTransactionStatus.Missing)
            .ToList();

        foreach (var missingTransaction in reappearedTransactions)
        {
            missingTransaction.MarkAsSeenInAMempool();
        }

        _dbTransactionsReappearedCount.Inc(reappearedTransactions.Count);

        var (_, dbUpdateMs) = await CodeStopwatch.TimeInMs(
            async () => await dbContext.SaveChangesAsync(token)
        );

        if (newTransactions.Count > 0 || reappearedTransactions.Count > 0)
        {
            _logger.LogInformation(
                "{NewTransactionsCount} transactions created and {ReappearedTransactionsCount} updated in {DbUpdatesMs}ms",
                newTransactions.Count,
                reappearedTransactions.Count,
                dbUpdateMs
            );
        }
    }

    private async Task HandleMissingPendingTransactions(
        HashSet<byte[]> seenTransactionIds,
        CancellationToken token
    )
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(token);

        var previouslyTrackedTransactionsNowMissingFromNodeMempools = await dbContext.MempoolTransactions
            .Where(mt => mt.Status == MempoolTransactionStatus.InNodeMempool)
            .Where(mempoolItem => !seenTransactionIds.Contains(mempoolItem.TransactionIdentifierHash))
            .ToListAsync(token);

        var timeouts = _aggregatorConfiguration.GetMempoolConfiguration();
        var currentTimestamp = SystemClock.Instance.GetCurrentInstant();

        foreach (var mempoolItem in previouslyTrackedTransactionsNowMissingFromNodeMempools)
        {
            if (!mempoolItem.SubmittedByThisGateway)
            {
                _dbTransactionsMarkedAsMissingCount.Inc();
                mempoolItem.MarkAsMissing();
                continue;
            }

            var nextResubmissionTime = mempoolItem.LastSubmittedToNodeTimestamp == null
                ? currentTimestamp
                : DateTimeExtensions.LatestOf(
                    mempoolItem.LastSubmittedToNodeTimestamp.Value + timeouts.MinDelayBetweenResubmissions,
                    currentTimestamp
                );

            var resubmissionLimit = mempoolItem.LastSubmittedToGatewayTimestamp!.Value + timeouts.StopResubmittingAfter;

            var canResubmit = nextResubmissionTime <= resubmissionLimit;

            if (canResubmit)
            {
                _dbTransactionsMarkedAsMissingCount.Inc();
                mempoolItem.MarkAsMissing();
            }
            else
            {
                _dbTransactionsMarkedAsFailedForTimeoutCount.Inc();
                mempoolItem.MarkAsFailed(
                    MempoolTransactionFailureReason.Timeout,
                    "The transaction keeps dropping out of the mempool, so we're not resubmitting it"
                );
            }
        }

        await dbContext.SaveChangesAsync(token);
    }
}
