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

using Common.Extensions;
using Common.Utilities;
using DataAggregator.GlobalServices;
using DataAggregator.GlobalWorkers;
using DataAggregator.NodeScopedServices;
using DataAggregator.NodeScopedServices.ApiReaders;
using Prometheus;
using RadixCoreApi.Generated.Model;

namespace DataAggregator.NodeScopedWorkers;

/// <summary>
/// Responsible for syncing the transaction stream from a node.
/// </summary>
public class NodeTransactionLogWorker : NodeWorker
{
    private static readonly Counter _failedFetchLoopsUnlabeled = Metrics
        .CreateCounter(
            "ng_node_fetch_transaction_batch_loop_error_total",
            "Number of fetch loop errors that failed.",
            new CounterConfiguration { LabelNames = new[] { "node" } }
        );

    private static readonly Histogram _totalFetchTimeSecondsUnlabeled = Metrics
        .CreateHistogram(
            "ng_node_fetch_transaction_batch_time_seconds",
            "Total time to fetch a batch of transactions.",
            new HistogramConfiguration
            {
                Buckets = Histogram.LinearBuckets(start: 0.1, width: 0.1, count: 50),
                LabelNames = new[] { "node" },
            }
        );

    /* Dependencies */
    private readonly ILogger<NodeTransactionLogWorker> _logger;
    private readonly ILedgerConfirmationService _ledgerConfirmationService;
    private readonly INodeConfigProvider _nodeConfigProvider;
    private readonly IServiceProvider _services;
    private readonly Counter.Child _failedFetchLoops;
    private readonly Histogram.Child _totalFetchTimeSeconds;

    /* Properties */
    private string NodeName => _nodeConfigProvider.NodeAppSettings.Name;

    // NB - So that we can get new transient dependencies (such as HttpClients) each iteration,
    //      we create these dependencies directly from the service provider each loop.
    public NodeTransactionLogWorker(
        ILogger<NodeTransactionLogWorker> logger,
        ILedgerConfirmationService ledgerConfirmationService,
        INodeConfigProvider nodeConfigProvider,
        IServiceProvider services
    )
        : base(logger, TimeSpan.FromMilliseconds(300), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(60))
    {
        _logger = logger;
        _ledgerConfirmationService = ledgerConfirmationService;
        _nodeConfigProvider = nodeConfigProvider;
        _services = services;
        _failedFetchLoops = _failedFetchLoopsUnlabeled.WithLabels(NodeName);
        _totalFetchTimeSeconds = _totalFetchTimeSecondsUnlabeled.WithLabels(NodeName);
    }

    public override bool IsEnabledByNodeConfiguration()
    {
        return _nodeConfigProvider.NodeAppSettings.Enabled && !_nodeConfigProvider.NodeAppSettings.DisabledForTransactionIndexing;
    }

    protected override async Task DoWork(CancellationToken cancellationToken)
    {
        await _failedFetchLoops.CountExceptionsAsync(() => FetchAndSubmitTransactions(cancellationToken));
    }

    private async Task FetchAndSubmitTransactions(CancellationToken stoppingToken)
    {
        const int FetchMaxBatchSize = 1000;

        var networkStatus = await _services.GetRequiredService<INetworkStatusReader>().GetNetworkStatus(stoppingToken);
        var nodeLedgerTip = networkStatus.CurrentStateIdentifier.StateVersion;
        var nodeLedgerTarget = networkStatus.SyncStatus.TargetStateVersion;

        _ledgerConfirmationService.SubmitNodeNetworkStatus(
            NodeName,
            nodeLedgerTip,
            networkStatus.CurrentStateIdentifier.TransactionAccumulator.ConvertFromHex(),
            nodeLedgerTarget
        );

        var toFetch = _ledgerConfirmationService.GetWhichTransactionsAreRequestedFromNode(NodeName);

        if (toFetch == null)
        {
            _logger.LogDebug(
                "No new transactions to fetch, sleeping for {DelayMs}ms",
                GetRemainingRestartDelay().Milliseconds
            );
            return;
        }

        var batchSize = Math.Min(
            (int)(toFetch.StateVersionInclusiveUpperBound - toFetch.StateVersionExclusiveLowerBound),
            FetchMaxBatchSize
        );

        var transactionResponse = await FetchTransactionsFromCoreApi(
            toFetch.StateVersionExclusiveLowerBound,
            batchSize,
            stoppingToken
        );

        _ledgerConfirmationService.SubmitTransactionsFromNode(
            NodeName,
            transactionResponse.Transactions
        );

        if (transactionResponse.Transactions.Count == 0)
        {
            _logger.LogDebug(
                "No new transactions found, sleeping for {DelayMs}ms",
                GetRemainingRestartDelay().Milliseconds
            );
        }
    }

    private async Task<CommittedTransactionsResponse> FetchTransactionsFromCoreApi(
        long fromStateVersion,
        int transactionsToPull,
        CancellationToken stoppingToken
    )
    {
        _logger.LogInformation(
            "Fetching up to {TransactionCount} transactions from version {FromStateVersion} from the core api",
            transactionsToPull,
            fromStateVersion
        );

        var (transactionsResponse, fetchTransactionsMs) = await CodeStopwatch.TimeInMs(
            () => _services.GetRequiredService<ITransactionLogReader>().GetTransactions(fromStateVersion, transactionsToPull, stoppingToken)
        );

        _totalFetchTimeSeconds.Observe(fetchTransactionsMs / 1000D);

        _logger.LogInformation(
            "Fetched {TransactionCount} transactions from version {FromStateVersion} from the core api in {FetchTransactionsMs}ms",
            transactionsResponse.Transactions.Count,
            fromStateVersion,
            fetchTransactionsMs
        );

        return transactionsResponse;
    }
}
