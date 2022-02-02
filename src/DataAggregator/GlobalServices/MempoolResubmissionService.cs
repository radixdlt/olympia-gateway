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
using Common.Exceptions;
using Common.Extensions;
using Common.Utilities;
using DataAggregator.Configuration;
using DataAggregator.Configuration.Models;
using DataAggregator.DependencyInjection;
using DataAggregator.Monitoring;
using DataAggregator.NodeScopedServices;
using DataAggregator.NodeScopedServices.ApiReaders;
using Microsoft.EntityFrameworkCore;
using NodaTime;
using Prometheus;
using RadixCoreApi.Generated.Model;

namespace DataAggregator.GlobalServices;

public interface IMempoolResubmissionService
{
    Task RunBatchOfResubmissions(CancellationToken token = default);
}

public class MempoolResubmissionService : IMempoolResubmissionService
{
    private static readonly LogLimiter _emptyResubmissionQueueLogLimiter = new(TimeSpan.FromSeconds(60), LogLevel.Information, LogLevel.Debug);

    private static readonly Gauge _resubmissionQueueSize = Metrics
        .CreateGauge(
            "ng_db_mempool_transactions_needing_resubmission_total",
            "Current number of transactions which have dropped out of mempools and need resubmitting."
        );

    private static readonly Counter _dbMempoolTransactionsMarkedAsResolvedButUnknownStatusCount = Metrics
        .CreateCounter(
            "ng_db_mempool_transactions_marked_resolved_but_unknown_status_count",
            "Number of mempool transactions marked as resolved but with an as-yet-unknown status during resubmission"
        );

    private static readonly Counter _dbMempoolTransactionsMarkedAsFailedDuringResubmissionCount = Metrics
        .CreateCounter(
            "ng_db_mempool_transactions_marked_failed_during_resubmission_count",
            "Number of mempool transactions marked as failed due to error during resubmission"
        );

    private static readonly Counter _dbMempoolTransactionsMarkedAsAssumedInNodeMempoolAfterResubmissionCount = Metrics
        .CreateCounter(
            "ng_db_mempool_transactions_assumed_in_node_mempool_after_resubmission_count",
            "Number of mempool transactions marked as InNodeMempool after resubmission"
        );

    private static readonly Counter _dbTransactionsMarkedAsFailedForTimeoutCount = Metrics
        .CreateCounter(
            "ng_db_mempool_transactions_marked_as_failed_for_timeout_count",
            "Number of mempool transactions in the DB marked as failed due to timeout as they won't be resubmitted"
        );

    private static readonly Counter _transactionResubmissionAttemptCount = Metrics
        .CreateCounter(
            "ng_construction_transaction_resubmission_attempt_count",
            "Number of transaction resubmission attempts"
        );

    private static readonly Counter _transactionResubmissionSuccessCount = Metrics
        .CreateCounter(
            "ng_construction_transaction_resubmission_success_count",
            "Number of transaction resubmission successes"
        );

    private static readonly Counter _transactionResubmissionErrorCount = Metrics
        .CreateCounter(
            "ng_construction_transaction_resubmission_error_count",
            "Number of transaction resubmission errors"
        );

    private static readonly Counter _transactionResubmissionResolutionByResultCount = Metrics
        .CreateCounter(
            "ng_construction_transaction_resubmission_resolution_count",
            "Number of various resolutions of transaction resubmissions",
            new CounterConfiguration { LabelNames = new[] { "result" } }
        );

    private readonly IServiceProvider _services;
    private readonly IDbContextFactory<AggregatorDbContext> _dbContextFactory;
    private readonly IAggregatorConfiguration _aggregatorConfiguration;
    private readonly INetworkConfigurationProvider _networkConfigurationProvider;
    private readonly ISystemStatusService _systemStatusService;
    private readonly ILogger<MempoolResubmissionService> _logger;

    public MempoolResubmissionService(
        IServiceProvider services,
        IDbContextFactory<AggregatorDbContext> dbContextFactory,
        IAggregatorConfiguration aggregatorConfiguration,
        INetworkConfigurationProvider networkConfigurationProvider,
        ISystemStatusService systemStatusService,
        ILogger<MempoolResubmissionService> logger
    )
    {
        _services = services;
        _dbContextFactory = dbContextFactory;
        _aggregatorConfiguration = aggregatorConfiguration;
        _networkConfigurationProvider = networkConfigurationProvider;
        _systemStatusService = systemStatusService;
        _logger = logger;
    }

    public async Task RunBatchOfResubmissions(CancellationToken token = default)
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(token);

        const int BatchSize = 30;

        var instantForTransactionChoosing = SystemClock.Instance.GetCurrentInstant();
        var mempoolConfiguration = _aggregatorConfiguration.GetMempoolConfiguration();

        var transactionsToResubmit = await SelectTransactionsToResubmit(dbContext, instantForTransactionChoosing, mempoolConfiguration, BatchSize, token);

        var submittedAt = SystemClock.Instance.GetCurrentInstant();

        // The timeout should be relative to the submittedAt time we save to the DB, so needs to include the time for initial db saving (which should be very quick).
        using var ctsWithSubmissionTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        ctsWithSubmissionTimeout.CancelAfter(mempoolConfiguration.ResubmissionNodeRequestTimeout.ToTimeSpan());

        var transactionsToResubmitWithNodes = MarkTransactionsAsFailedForTimeoutOrPendingResubmissionToRandomNode(
            mempoolConfiguration,
            transactionsToResubmit,
            submittedAt
        );

        // We save as assumed successfully submitted here to lock in the fact we're resubmitting - in case we hit an
        // exception below and fail to resubmit. By virtue of the ConcurrencyToken on the Status, this protects us
        // against resubmitting the same transaction multiple times - even if (eg) two data aggregators are running.
        await dbContext.SaveChangesAsync(token);

        await ResubmitAllAndUpdateTransactionStatusesOnFailure(mempoolConfiguration, transactionsToResubmitWithNodes, submittedAt, ctsWithSubmissionTimeout.Token);

        await dbContext.SaveChangesAsync(token);
    }

    private async Task<List<MempoolTransaction>> SelectTransactionsToResubmit(
        AggregatorDbContext dbContext,
        Instant instantForTransactionChoosing,
        MempoolConfiguration mempoolConfiguration,
        int batchSize,
        CancellationToken token
    )
    {
        var transactionsToResubmit =
            await GetMempoolTransactionsNeedingResubmission(instantForTransactionChoosing, mempoolConfiguration, dbContext)
                .OrderBy(mt => mt.LastSubmittedToNodeTimestamp)
                .Take(batchSize)
                .ToListAsync(token);

        var totalTransactionsNeedingResubmission = transactionsToResubmit.Count < batchSize
            ? transactionsToResubmit.Count
            : await GetMempoolTransactionsNeedingResubmission(instantForTransactionChoosing, mempoolConfiguration, dbContext)
                .CountAsync(token);

        _resubmissionQueueSize.Set(totalTransactionsNeedingResubmission);

        if (totalTransactionsNeedingResubmission == 0)
        {
            _logger.Log(_emptyResubmissionQueueLogLimiter.GetLogLevel(), "There are no transactions needing resubmission");
        }
        else if (totalTransactionsNeedingResubmission <= batchSize)
        {
            _logger.LogInformation(
                "Preparing to resubmit all {TransactionsCount} transactions needing resubmission",
                totalTransactionsNeedingResubmission
            );
        }
        else
        {
            _logger.LogWarning(
                "There are {TotalCount} transactions needing resubmission, but we are only resubmitting {BatchSize} this batch",
                totalTransactionsNeedingResubmission,
                transactionsToResubmit.Count
            );
        }

        return transactionsToResubmit;
    }

    private List<MempoolTransactionWithChosenNode> MarkTransactionsAsFailedForTimeoutOrPendingResubmissionToRandomNode(
        MempoolConfiguration mempoolConfiguration,
        List<MempoolTransaction> transactionsWantingResubmission,
        Instant submittedAt
    )
    {
        var transactionsToResubmitWithNodes = new List<MempoolTransactionWithChosenNode>();

        foreach (var transaction in transactionsWantingResubmission)
        {
            var resubmissionLimit = transaction.LastSubmittedToGatewayTimestamp!.Value + mempoolConfiguration.StopResubmittingAfter;

            var canResubmit = submittedAt <= resubmissionLimit;

            if (canResubmit)
            {
                var nodeToSubmitTo = GetRandomCoreApi();
                _dbMempoolTransactionsMarkedAsAssumedInNodeMempoolAfterResubmissionCount.Inc();
                transaction.MarkAsAssumedSuccessfullySubmittedToNode(nodeToSubmitTo.Name, submittedAt);
                transactionsToResubmitWithNodes.Add(new MempoolTransactionWithChosenNode(transaction, nodeToSubmitTo));
            }
            else
            {
                _dbTransactionsMarkedAsFailedForTimeoutCount.Inc();
                transaction.MarkAsFailed(
                    MempoolTransactionFailureReason.Timeout,
                    "The transaction keeps dropping out of the mempool, so we're not resubmitting it"
                );
            }
        }

        return transactionsToResubmitWithNodes;
    }

    private record MempoolTransactionWithChosenNode(MempoolTransaction MempoolTransaction, NodeAppSettings Node);

    private IQueryable<MempoolTransaction> GetMempoolTransactionsNeedingResubmission(
        Instant currentTimestamp,
        MempoolConfiguration mempoolConfiguration,
        AggregatorDbContext dbContext
    )
    {
        var allowResubmissionIfLastSubmittedBefore = currentTimestamp - mempoolConfiguration.MinDelayBetweenResubmissions;

        var allowResubmissionIfDroppedOutOfMempoolBefore = currentTimestamp - mempoolConfiguration.MinDelayBetweenMissingFromMempoolAndResubmission;

        var isEssentiallySyncedUpNow = _systemStatusService.IsTopOfDbLedgerValidatorCommitTimestampCloseToPresent(Duration.FromSeconds(60));

        return dbContext.MempoolTransactions
            .Where(mt =>
                mt.SubmittedByThisGateway
                && (
                    /* Transactions get marked Missing way by the MempoolTrackerService */
                    mt.Status == MempoolTransactionStatus.Missing

                    /* If we're synced up now, try submitting transactions with unknown status again. They almost
                       certainly failed due to a real double spend - so we'll detect it now and can mark them failed */
                    || (isEssentiallySyncedUpNow && mt.Status == MempoolTransactionStatus.ResolvedButUnknownTillSyncedUp)
                )
                && mt.LastDroppedOutOfMempoolTimestamp!.Value < allowResubmissionIfDroppedOutOfMempoolBefore
                && mt.LastSubmittedToNodeTimestamp!.Value < allowResubmissionIfLastSubmittedBefore
            );
    }

    private async Task ResubmitAllAndUpdateTransactionStatusesOnFailure(
        MempoolConfiguration mempoolConfiguration,
        List<MempoolTransactionWithChosenNode> transactionsToResubmitWithNodes,
        Instant submittedAt,
        CancellationToken token
    )
    {
        var submissionResults = await ResubmitAll(transactionsToResubmitWithNodes, token);

        foreach (var (transaction, failed, failureReason, failureExplanation, nodeName) in submissionResults)
        {
            if (!failed)
            {
                continue;
            }

            var isDoubleSpendWhichCouldBeItself =
                failureReason!.Value == MempoolTransactionFailureReason.DoubleSpend
                && !_systemStatusService.GivenClockDriftBoundIsTopOfDbLedgerValidatorCommitTimestampConfidentlyAfter(
                    mempoolConfiguration.AssumedBoundOnNetworkLedgerDataAggregatorClockDrift,
                    transaction.LastDroppedOutOfMempoolTimestamp!.Value
                );

            if (isDoubleSpendWhichCouldBeItself)
            {
                // If we're not synced up, we can't be sure if the double spend from the node is actually just the
                // transaction itself having already hit the ledger! Let's just assume it submitted correctly and
                // resubmit.

                _dbMempoolTransactionsMarkedAsResolvedButUnknownStatusCount.Inc();
                transaction.MarkAsResolvedButUnknownAfterSubmittedToNode(nodeName, submittedAt);
            }
            else
            {
                _dbMempoolTransactionsMarkedAsFailedDuringResubmissionCount.Inc();
                transaction.MarkAsFailedAfterSubmittedToNode(nodeName, failureReason.Value, failureExplanation!, submittedAt);
            }
        }
    }

    private record SubmissionResult(
        MempoolTransaction MempoolTransaction,
        bool TransactionInvalid,
        MempoolTransactionFailureReason? FailureReason,
        string? SubmissionFailureExplanation,
        string NodeName
    );

    private async Task<SubmissionResult[]> ResubmitAll(List<MempoolTransactionWithChosenNode> transactionsToResubmit, CancellationToken token)
    {
        return await Task.WhenAll(transactionsToResubmit.Select(t => Resubmit(t, token)));
    }

    // NB - The error handling here should mirror the resubmission in ConstructionAndSubmissionService
    private async Task<SubmissionResult> Resubmit(MempoolTransactionWithChosenNode transactionWithNode, CancellationToken cancellationToken)
    {
        _transactionResubmissionAttemptCount.Inc();
        var transaction = transactionWithNode.MempoolTransaction;
        var chosenNode = transactionWithNode.Node;
        using var nodeScope = _services.CreateScope();
        nodeScope.ServiceProvider.GetRequiredService<INodeConfigProvider>().NodeAppSettings = chosenNode;
        var coreApiProvider = nodeScope.ServiceProvider.GetRequiredService<ICoreApiProvider>();

        var submitRequest = new ConstructionSubmitRequest(
            _networkConfigurationProvider.GetNetworkIdentifierForApiRequests(),
            transaction.Payload.ToHex()
        );

        try
        {
            var result = await CoreApiErrorWrapper.ExtractCoreApiErrors(async () => await
                coreApiProvider.ConstructionApi.ConstructionSubmitPostAsync(submitRequest, cancellationToken)
            );
            _transactionResubmissionSuccessCount.Inc();
            if (result.Duplicate)
            {
                _transactionResubmissionResolutionByResultCount.WithLabels("node_marks_as_duplicate").Inc();
            }
            else
            {
                _transactionResubmissionResolutionByResultCount.WithLabels("success").Inc();
            }

            return new SubmissionResult(transaction, false, null, null, chosenNode.Name);
        }
        catch (WrappedCoreApiException<SubstateDependencyNotFoundError> ex)
        {
            _transactionResubmissionErrorCount.Inc();
            _transactionResubmissionResolutionByResultCount.WithLabels("substate_missing_or_already_used").Inc();
            _logger.LogDebug(
                "Dropping transaction because a substate identifier it used is missing or already downed - possibly it's already been committed. Substate Identifier: {Substate}",
                ex.Error.SubstateIdentifierNotFound.Identifier
            );
            var failureExplanation = "Double spend on resubmission";
            return new SubmissionResult(transaction, true, MempoolTransactionFailureReason.DoubleSpend, failureExplanation, chosenNode.Name);
        }
        catch (WrappedCoreApiException ex) when (ex.Properties.Transience == Transience.Permanent)
        {
            _transactionResubmissionErrorCount.Inc();
            _transactionResubmissionResolutionByResultCount.WithLabels("unknown_permanent_error").Inc();
            var failureExplanation = $"Core API Exception: {ex.Error.GetType().Name} on resubmission";
            return new SubmissionResult(transaction, true, MempoolTransactionFailureReason.Unknown, failureExplanation, chosenNode.Name);
        }
        catch (OperationCanceledException)
        {
            _transactionResubmissionErrorCount.Inc();
            _transactionResubmissionResolutionByResultCount.WithLabels("request_timeout").Inc();
            return new SubmissionResult(transaction, false, null, null, chosenNode.Name);
        }
        catch (Exception)
        {
            // Unsure of what the problem is -- it could be that the connection died or there was an internal server error
            // We have to assume the submission may have succeeded and wait for resubmission if not.
            _transactionResubmissionErrorCount.Inc();
            _transactionResubmissionResolutionByResultCount.WithLabels("unknown_error").Inc();
            return new SubmissionResult(transaction, false, null, null, chosenNode.Name);
        }
    }

    private NodeAppSettings GetRandomCoreApi()
    {
        return _aggregatorConfiguration.GetNodes()
            .Where(n => n.Enabled && !n.DisabledForConstruction)
            .GetRandomBy(n => (double)n.RequestWeighting);
    }
}
