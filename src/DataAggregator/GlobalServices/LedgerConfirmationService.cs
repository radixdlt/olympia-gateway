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

using Common.Database.Models.SingleEntries;
using Common.Extensions;
using Common.Utilities;
using DataAggregator.Configuration;
using DataAggregator.Configuration.Models;
using DataAggregator.Exceptions;
using DataAggregator.LedgerExtension;
using DataAggregator.Monitoring;
using NodaTime;
using Prometheus;
using RadixCoreApi.Generated.Model;
using System.Collections.Concurrent;

namespace DataAggregator.GlobalServices;

public interface ILedgerConfirmationService
{
    // This method is to be called from the global LedgerExtensionWorker
    Task HandleLedgerExtensionIfQuorum(CancellationToken token);

    // Below are to be called from the node transaction log workers - to communicate with the LedgerConfirmationService
    void SubmitNodeNetworkStatus(string nodeName, long ledgerTipStateVersion, byte[] ledgerTipAccumulator, long targetStateVersion);

    void SubmitTransactionsFromNode(string nodeName, List<CommittedTransaction> transactions);

    TransactionsRequested? GetWhichTransactionsAreRequestedFromNode(string nodeName);
}

public record TransactionsRequested(long StateVersionExclusiveLowerBound, long StateVersionInclusiveUpperBound);

/// <summary>
/// This service is responsible for controlling the NodeTransactionLogWorkers, and deciding on / committing when
/// a quorum is reached.
/// </summary>
public class LedgerConfirmationService : ILedgerConfirmationService
{
    /* Global Metrics - Quorum/Sync related - ie ledger_node prefix */
    private static readonly Gauge _quorumExistsStatus = Metrics
        .CreateGauge(
            "ng_ledger_sync_quorum_exists_status",
            "Whether enough nodes agree to continue committing transaction to the DB. 1 = true, 0.5 = unknown, 0 = false. (if 0, it's a critical alarm)."
        );

    private static readonly Gauge _quorumExtensionConsistentStatus = Metrics
        .CreateGauge(
            "ng_ledger_sync_quorum_extension_consistent_status",
            "If a node quorum exists for a ledger extension, whether it agrees with the existing DB accumulator and is internally consistent. 1 = true, 0.5 = unknown, 0 = false. If 0, it's a critical alarm."
        );

    private static readonly Gauge _sufficientlySyncedUpNodesTotal = Metrics
        .CreateGauge(
            "ng_ledger_sync_sufficiently_synced_up_nodes_total",
            "The number of nodes which are sufficiently synced up."
        );

    private static readonly Gauge _sufficientlySyncedUpNodesTrustWeightingTotal = Metrics
        .CreateGauge(
            "ng_ledger_sync_sufficiently_synced_up_nodes_trust_weighting_total",
            "The trust weighting of all nodes which are currently sufficiently synced up"
        );

    private static readonly Gauge _configuredNodesTotal = Metrics
        .CreateGauge(
            "ng_ledger_sync_configured_nodes_total",
            "The number of nodes which are configured for transaction syncing."
        );

    private static readonly Gauge _configuredNodesTrustWeightingTotal = Metrics
        .CreateGauge(
            "ng_ledger_sync_configured_nodes_trust_weighting_total",
            "The trust weighting of all nodes which are currently configured for transaction syncing."
        );

    private static readonly Gauge _ledgerNodeTrustWeightingRequiredForQuorum = Metrics
        .CreateGauge(
            "ng_ledger_sync_trust_weighting_required_for_quorum_total",
            "The trust weighting currently required for quorum"
        );

    private static readonly Gauge _ledgerNodeTrustWeightingRequiredForQuorumIfAllNodesSufficientlySynced = Metrics
        .CreateGauge(
            "ng_ledger_sync_trust_weighting_required_for_quorum_if_all_nodes_sufficiently_synced_total",
            "The trust weighting required for quorum, if/once all nodes are synced up"
        );

    /* Global Metrics - Quorum/Sync related - ie ledger_commit prefix */

    private static readonly Histogram _batchCommitTimeSeconds = Metrics
        .CreateHistogram(
            "ng_ledger_commit_batch_commit_time_seconds",
            "Total time to commit a batch of transactions.",
            new HistogramConfiguration { Buckets = Histogram.LinearBuckets(start: 0.2, width: 0.2, count: 100) }
        );

    private static readonly Counter _ledgerCommittedTransactionsCount = Metrics
        .CreateCounter(
            "ng_ledger_commit_committed_transactions_count",
            "Count of committed transactions."
        );

    private static readonly Gauge _ledgerLastCommitTimestamp = Metrics
        .CreateGauge(
            "ng_ledger_commit_last_commit_timestamp_seconds",
            "Unix timestamp of the last DB ledger commit."
        );

    private static readonly Gauge _ledgerStateVersion = Metrics
        .CreateGauge(
            "ng_ledger_commit_tip_state_version",
            "The state version of the top of the DB ledger."
        );

    private static readonly Gauge _ledgerUnixRoundTimestamp = Metrics
        .CreateGauge(
            "ng_ledger_commit_tip_round_unix_timestamp_seconds",
            "Unix timestamp of the round at the top of the DB ledger."
        );

    /* Per-Node Metrics */
    private static readonly Gauge _nodeLedgerTipStateVersion = Metrics
        .CreateGauge(
            "ng_node_ledger_tip_state_version",
            "The state version at the tip of the node's ledger.",
            new GaugeConfiguration { LabelNames = new[] { "node" } }
        );

    private static readonly Gauge _nodeLedgerTargetStateVersion = Metrics
        .CreateGauge(
            "ng_node_ledger_target_state_version",
            "The state version which the node reports as the highest seen on the network.",
            new GaugeConfiguration { LabelNames = new[] { "node" } }
        );

    private static readonly Gauge _nodeLedgerTipIsConsistentWithQuorumStatus = Metrics
        .CreateGauge(
            "ng_node_ledger_tip_is_consistent_with_quorum_status",
            "If the node's ledger tip is consistent with the committed quorum. 1 = true, 0.5 = unknown, 0 = false. If 0, this is an important warning alarm - this node will need to be fixed.",
            new GaugeConfiguration { LabelNames = new[] { "node" } }
        );

    /* Dependencies */
    private readonly ILogger<LedgerConfirmationService> _logger;
    private readonly IAggregatorConfiguration _aggregatorConfiguration;
    private readonly ISystemStatusService _systemStatusService;
    private readonly ILedgerExtenderService _ledgerExtenderService;

    /* Variables */
    private readonly LruCache<long, byte[]> _quorumAccumulatorCacheByStateVersion = new(2000);
    private readonly ConcurrentDictionary<string, long> _latestLedgerTipByNode = new();
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<long, CommittedTransaction>> _transactionsByNode = new();
    private TransactionSummary? _knownTopOfCommittedLedger;

    /* Properties */
    private LedgerConfirmationConfiguration Config => _aggregatorConfiguration.GetLedgerConfirmationConfiguration();

    private IList<NodeAppSettings> TransactionNodes { get; set; } = new List<NodeAppSettings>();

    public LedgerConfirmationService(
        ILogger<LedgerConfirmationService> logger,
        IAggregatorConfiguration aggregatorConfiguration,
        ISystemStatusService systemStatusService,
        ILedgerExtenderService ledgerExtenderService
    )
    {
        _logger = logger;
        _aggregatorConfiguration = aggregatorConfiguration;
        _systemStatusService = systemStatusService;
        _ledgerExtenderService = ledgerExtenderService;

        _quorumExistsStatus.SetStatus(MetricStatus.Unknown);
        _quorumExtensionConsistentStatus.SetStatus(MetricStatus.Unknown);
    }

    /// <summary>
    /// To be run by the (single-threaded) ledger extender worker.
    /// </summary>
    public async Task HandleLedgerExtensionIfQuorum(CancellationToken token)
    {
        await LoadTopOfDbLedger(token);

        PrepareForLedgerExtensionCheck();
        var transactions = ConstructQuorumLedgerExtension();

        if (transactions.Count == 0)
        {
            return;
        }

        var ledgerExtension = GenerateConsistentLedgerExtension(transactions);
        var latestSyncStatus = new SyncTarget { TargetStateVersion = GetTargetStateVersion() };

        var (commitReport, totalCommitMs) = await CodeStopwatch.TimeInMs(
            () => _ledgerExtenderService.CommitTransactions(ledgerExtension, latestSyncStatus, token)
        );

        HandleLedgerExtensionSuccess(ledgerExtension, totalCommitMs, commitReport);
    }

    /// <summary>
    /// To be called from the node worker.
    /// </summary>
    public void SubmitNodeNetworkStatus(
        string nodeName,
        long ledgerTipStateVersion,
        byte[] ledgerTipAccumulator,
        long targetStateVersion
    )
    {
        _latestLedgerTipByNode[nodeName] = ledgerTipStateVersion;
        _nodeLedgerTipStateVersion.WithLabels(nodeName).Set(ledgerTipStateVersion);
        _nodeLedgerTargetStateVersion.WithLabels(nodeName).Set(targetStateVersion);

        if (ledgerTipStateVersion > _knownTopOfCommittedLedger?.StateVersion)
        {
            // We handle consistency checks ahead of the commit point in the ConstructQuorumLedgerExtension method
            return;
        }

        var cachedAccumulator = _quorumAccumulatorCacheByStateVersion.GetOrDefault(ledgerTipStateVersion);

        if (cachedAccumulator == null)
        {
            // Ledger Tip is too far behind -- so don't report on consistency.
            // We could change this to do a database look-up in future to give a consistency check.
            _nodeLedgerTipIsConsistentWithQuorumStatus.WithLabels(nodeName).SetStatus(MetricStatus.Unknown);
        }
        else if (cachedAccumulator.BytesAreEqual(ledgerTipAccumulator))
        {
            _nodeLedgerTipIsConsistentWithQuorumStatus.WithLabels(nodeName).SetStatus(MetricStatus.Yes);
        }
        else
        {
            _nodeLedgerTipIsConsistentWithQuorumStatus.WithLabels(nodeName).SetStatus(MetricStatus.No);
        }
    }

    /// <summary>
    /// To be called from the node worker.
    /// </summary>
    public void SubmitTransactionsFromNode(
        string nodeName,
        List<CommittedTransaction> transactions
    )
    {
        if (!_latestLedgerTipByNode.ContainsKey(nodeName))
        {
            throw new Exception("The node's ledger tip must be written first");
        }

        var transactionStoreForNode = GetTransactionsForNode(nodeName);
        foreach (var transaction in transactions)
        {
            transactionStoreForNode[transaction.CommittedStateIdentifier.StateVersion] = transaction;
        }
    }

    /// <summary>
    /// To be called from the node worker.
    /// </summary>
    public TransactionsRequested? GetWhichTransactionsAreRequestedFromNode(string nodeName)
    {
        var currentTopOfLedger = _knownTopOfCommittedLedger;
        if (currentTopOfLedger == null)
        {
            return null;
        }

        var exclusiveLowerBound = currentTopOfLedger.StateVersion;
        var inclusiveUpperBound = currentTopOfLedger.StateVersion + Config.MaxTransactionPipelineSizePerNode;

        var firstMissingStateVersionGap = GetFirstStateVersionGapForNode(nodeName, exclusiveLowerBound, inclusiveUpperBound);

        return (firstMissingStateVersionGap == null || firstMissingStateVersionGap > inclusiveUpperBound)
            ? null
            : new TransactionsRequested(firstMissingStateVersionGap.Value - 1, inclusiveUpperBound);
    }

    private void PrepareForLedgerExtensionCheck()
    {
        // We persist this to avoid excessive allocations; but update it at the start of each loop in case the config has changed
        TransactionNodes = _aggregatorConfiguration.GetNodes()
            .Where(n => n.Enabled && !n.DisabledForTransactionIndexing)
            .ToList();
    }

    private List<CommittedTransaction> ConstructQuorumLedgerExtension()
    {
        var extension = new List<CommittedTransaction>();

        var startStateVersion = _knownTopOfCommittedLedger!.StateVersion + 1;
        var trustRequirements = ComputeTrustWeightingRequirements();

        if (trustRequirements.TrustWeightingAvailableAcrossAllNodes == 0)
        {
            _logger.LogWarning("Total trust weighting across all nodes is zero - perhaps no nodes are configured for transaction reading?");
            return extension;
        }

        if (trustRequirements.TrustWeightingRequiredForQuorumAtPresentTime == 0)
        {
            _logger.LogWarning("Total trust weighting required for extension is zero - likely the system is either yet to read from nodes, or none of the nodes are close enough to synced up");
            return extension;
        }

        for (var stateVersion = startStateVersion; stateVersion < startStateVersion + Config.MaxCommitBatchSize; stateVersion++)
        {
            var (chosenTransaction, trustAlreadyCommittedByNodes, inconsistentNodeNames) = FindMostTrustedTransaction(stateVersion);

            var haveQuorum = chosenTransaction != null && chosenTransaction.Trust >= trustRequirements.TrustWeightingRequiredForQuorumAtPresentTime;

            if (haveQuorum)
            {
                foreach (var inconsistentNodeName in inconsistentNodeNames)
                {
                    _nodeLedgerTipIsConsistentWithQuorumStatus.WithLabels(inconsistentNodeName).SetStatus(MetricStatus.No);
                }

                foreach (var consistentNodeName in chosenTransaction!.NodeNames)
                {
                    _nodeLedgerTipIsConsistentWithQuorumStatus.WithLabels(consistentNodeName).SetStatus(MetricStatus.Yes);
                }

                extension.Add(chosenTransaction.Transaction);
                continue;
            }

            /*
             * It's likely we simply just don't have enough nodes contributing yet.
             * But, if it's not possible to reach quorum even with more nodes contributing - then we need to worry.
             * So let's try a couple of possibilities
             */
            var trustWeightingOfBestTransaction = chosenTransaction?.Trust ?? 0m;

            var remainingTrustPossibleFromSufficientlySyncedNodes =
                trustRequirements.TrustWeightingOfSufficientlySyncedUpNodes - trustAlreadyCommittedByNodes;

            if (
                trustWeightingOfBestTransaction + remainingTrustPossibleFromSufficientlySyncedNodes <
                trustRequirements.TrustWeightingRequiredForQuorumAtPresentTime
            )
            {
                // We can't make headway with all sufficiently synced up nodes - let's set this to Unknown until
                // we get more nodes synced up...
                _quorumExistsStatus.SetStatus(MetricStatus.Unknown);
            }

            var remainingTrustPossibleFromAllNodes =
                trustRequirements.TrustWeightingAvailableAcrossAllNodes - trustAlreadyCommittedByNodes;

            if (
                trustWeightingOfBestTransaction + remainingTrustPossibleFromAllNodes <
                trustRequirements.TrustWeightingRequiredForQuorumIfAllNodesAvailableForQuorum
            )
            {
                // Even with all nodes synced up, we wouldn't reach a quorum - mark this as a critical alarm!
                _quorumExistsStatus.SetStatus(MetricStatus.No);
            }

            break;
        }

        if (extension.Count > 0)
        {
            _quorumExistsStatus.SetStatus(MetricStatus.Yes);
        }

        return extension;
    }

    private async Task LoadTopOfDbLedger(CancellationToken token)
    {
        var (topOfLedger, readTopOfLedgerMs) = await CodeStopwatch.TimeInMs(
            () => _ledgerExtenderService.GetTopOfLedger(token)
        );
        UpdateRecordsOfTopOfLedger(topOfLedger);
        _logger.LogDebug(
            "Top of DB ledger is at state version {StateVersion} (read in {ReadTopOfLedgerMs}ms)",
            topOfLedger.StateVersion,
            readTopOfLedgerMs
        );
    }

    private void HandleLedgerExtensionSuccess(ConsistentLedgerExtension ledgerExtension, long totalCommitMs,
        CommitTransactionsReport commitReport)
    {
        ReportOnLedgerExtensionSuccess(ledgerExtension, totalCommitMs, commitReport);
        AddAccumulatorsToCache(ledgerExtension);
        UpdateRecordsOfTopOfLedger(commitReport.FinalTransaction);

        // NB - this must come after UpdateTopOfLedgerVariable so that the nodes don't try to fill the gap that's
        //      created when we remove the transactions below it
        StopTrackingTransactionsUpToStateVersion(commitReport.FinalTransaction.StateVersion);
    }

    private void ReportOnLedgerExtensionSuccess(ConsistentLedgerExtension ledgerExtension, long totalCommitMs, CommitTransactionsReport commitReport)
    {
        _systemStatusService.RecordTransactionsCommitted();

        _batchCommitTimeSeconds.Observe(totalCommitMs / 1000D);
        _ledgerCommittedTransactionsCount.Inc(commitReport.TransactionsCommittedCount);
        _ledgerLastCommitTimestamp.Set(SystemClock.Instance.GetCurrentInstant().ToUnixTimeSeconds());

        _logger.LogInformation(
            "Committed {TransactionCount} transactions to the DB in {TotalCommitTransactionsMs}ms [EntitiesTouched={DbEntriesWritten},TxnContentDbActions={TransactionContentDbActionsCount}]",
            ledgerExtension.TransactionData.Count,
            totalCommitMs,
            commitReport.DbEntriesWritten,
            commitReport.TransactionContentDbActionsCount
        );

        _logger.LogInformation(
            "[TimeSplitsInMs: RawTxns={RawTxnPersistenceMs},Mempool={MempoolTransactionUpdateMs},TxnContentHandling={TxnContentHandlingMs},DbDependencyLoading={DbDependenciesLoadingMs},LocalActionPlanning={LocalDbContextActionsMs},DbPersistence={DbPersistanceMs}]",
            commitReport.RawTxnPersistenceMs,
            commitReport.MempoolTransactionUpdateMs,
            commitReport.TransactionContentHandlingMs,
            commitReport.DbDependenciesLoadingMs,
            commitReport.LocalDbContextActionsMs,
            commitReport.DbPersistanceMs
        );

        var committedTransactionSummary = commitReport.FinalTransaction;
        _logger.LogInformation(
            "[NewDbLedgerTip: StateVersion={LedgerStateVersion},Epoch={LedgerEpoch},IndexInEpoch={LedgerIndexInEpoch},RoundTimestamp={RoundTimestamp}]",
            committedTransactionSummary.StateVersion,
            committedTransactionSummary.Epoch,
            committedTransactionSummary.IndexInEpoch,
            committedTransactionSummary.RoundTimestamp.AsUtcIsoDateToSecondsForLogs()
        );
    }

    private void AddAccumulatorsToCache(ConsistentLedgerExtension ledgerExtension)
    {
        foreach (var transactionData in ledgerExtension.TransactionData)
        {
            _quorumAccumulatorCacheByStateVersion.Set(
                transactionData.TransactionSummary.StateVersion,
                transactionData.TransactionSummary.TransactionAccumulator
            );
        }
    }

    private void UpdateRecordsOfTopOfLedger(TransactionSummary topOfLedger)
    {
        _knownTopOfCommittedLedger = topOfLedger;
        RecordTopOfDbLedgerMetrics(topOfLedger);
        _systemStatusService.SetTopOfDbLedger(topOfLedger);
    }

    private void RecordTopOfDbLedgerMetrics(TransactionSummary topOfLedger)
    {
        _ledgerStateVersion.Set(topOfLedger.StateVersion);
        _ledgerUnixRoundTimestamp.Set(topOfLedger.RoundTimestamp.ToUnixTimeSeconds());
    }

    private void StopTrackingTransactionsUpToStateVersion(long committedStateVersion)
    {
        foreach (var (_, transactions) in _transactionsByNode)
        {
            var stateVersionsToRemove = transactions.Keys.Where(k => k <= committedStateVersion).ToList();
            foreach (var stateVersion in stateVersionsToRemove)
            {
                transactions.TryRemove(stateVersion, out _);
            }
        }
    }

    private record MostTrustedTransactionReport(
        TransactionClaim? Best,
        decimal TotalTrustCommittedByNodes,
        List<string> InconsistentNodeNames
    );

    private record TransactionClaim(CommittedTransaction Transaction, List<string> NodeNames, decimal Trust);

    private MostTrustedTransactionReport FindMostTrustedTransaction(long stateVersion)
    {
        var transactionsWithTrust = _transactionsByNode
            .Select(n => new
            {
                NodeName = n.Key,
                Transaction = n.Value.GetValueOrDefault(stateVersion),
                Trust = GetTrustForNode(n.Key),
            })
            .Where(x => x.Transaction != null)
            .ToList();

        if (transactionsWithTrust.Count == 0)
        {
            return new MostTrustedTransactionReport(null, 0m, new List<string>());
        }

        var groupedTransactions = transactionsWithTrust
            .GroupBy(t => t.Transaction!.CommittedStateIdentifier.TransactionAccumulator)
            .Select(grouping => new TransactionClaim(
                grouping.First().Transaction!,
                grouping.Select(g => g.NodeName).ToList(),
                grouping.Sum(x => x.Trust)
            ))
            .ToList();

        var totalTrust = groupedTransactions.Sum(t => t.Trust);
        var orderedTransactionClaims = groupedTransactions.OrderByDescending(t => t.Trust).ToList();
        var topTransaction = orderedTransactionClaims.First();

        var inconsistentNodeNames = orderedTransactionClaims.Skip(1)
            .SelectMany(t => t.NodeNames)
            .ToList();

        return new MostTrustedTransactionReport(topTransaction, totalTrust, inconsistentNodeNames);
    }

    private ConsistentLedgerExtension GenerateConsistentLedgerExtension(
        List<CommittedTransaction> transactions
    )
    {
        var transactionData = new List<CommittedTransactionData>();
        var transactionBatchParentSummary = _knownTopOfCommittedLedger!;
        var currentParentSummary = transactionBatchParentSummary;
        try
        {
            foreach (var transaction in transactions)
            {
                var summary = TransactionSummarisation.GenerateSummary(currentParentSummary, transaction);
                var contents = transaction.Metadata.Hex.ConvertFromHex();

                TransactionConsistency.AssertTransactionHashCorrect(contents, summary.TransactionIdentifierHash);
                TransactionConsistency.AssertChildTransactionConsistent(currentParentSummary, summary);

                transactionData.Add(new CommittedTransactionData(transaction, summary, contents));
                currentParentSummary = summary;
            }

            _quorumExtensionConsistentStatus.SetStatus(MetricStatus.Yes);
        }
        catch (InvalidLedgerCommitException)
        {
            _quorumExtensionConsistentStatus.SetStatus(MetricStatus.No);
            throw;
        }
        catch (InconsistentLedgerException)
        {
            _quorumExtensionConsistentStatus.SetStatus(MetricStatus.No);
            throw;
        }

        return new ConsistentLedgerExtension(transactionBatchParentSummary, transactionData);
    }

    private long GetTargetStateVersion()
    {
        var ledgerTips = _latestLedgerTipByNode.Values.ToList();

        if (ledgerTips.Count == 0)
        {
            throw new Exception("At least one ledger tip must have been submitted");
        }

        return ledgerTips.Max();
    }

    private record TrustWeightingReport(
        decimal TrustWeightingAvailableAcrossAllNodes,
        decimal TrustWeightingOfSufficientlySyncedUpNodes,
        decimal TrustWeightingRequiredForQuorumAtPresentTime,
        decimal TrustWeightingRequiredForQuorumIfAllNodesAvailableForQuorum
    );

    private TrustWeightingReport ComputeTrustWeightingRequirements()
    {
        var sufficientlySyncedUpNodes = TransactionNodes
            .Where(node => IsSufficientlySyncedUp(node.Name))
            .ToList();

        var sufficientlySyncedUpNodesTrustWeighting = sufficientlySyncedUpNodes.Sum(node => node.TrustWeighting);

        _sufficientlySyncedUpNodesTotal.Set(sufficientlySyncedUpNodes.Count);
        _sufficientlySyncedUpNodesTrustWeightingTotal.Set((double)sufficientlySyncedUpNodesTrustWeighting);

        var trustWeightingAcrossAllNodes = TransactionNodes.Sum(node => node.TrustWeighting);

        _configuredNodesTotal.Set(TransactionNodes.Count());
        _configuredNodesTrustWeightingTotal.Set((double)trustWeightingAcrossAllNodes);

        var trustWeightingTotalUsedForQuorumCalculation = Config.OnlyUseSufficientlySyncedUpNodesForQuorumCalculation
            ? sufficientlySyncedUpNodesTrustWeighting
            : trustWeightingAcrossAllNodes;

        var trustWeightingForQuorum = Config.QuorumRequiresTrustProportion * trustWeightingTotalUsedForQuorumCalculation;
        var trustWeightingForQuorumIfAllSyncedUp = Config.QuorumRequiresTrustProportion * trustWeightingAcrossAllNodes;

        _ledgerNodeTrustWeightingRequiredForQuorum.Set((double)trustWeightingForQuorum);
        _ledgerNodeTrustWeightingRequiredForQuorumIfAllNodesSufficientlySynced.Set((double)trustWeightingForQuorumIfAllSyncedUp);

        return new TrustWeightingReport(
            TrustWeightingAvailableAcrossAllNodes: trustWeightingAcrossAllNodes,
            TrustWeightingOfSufficientlySyncedUpNodes: sufficientlySyncedUpNodesTrustWeighting,
            TrustWeightingRequiredForQuorumAtPresentTime: trustWeightingForQuorum,
            TrustWeightingRequiredForQuorumIfAllNodesAvailableForQuorum: trustWeightingForQuorumIfAllSyncedUp
        );
    }

    private decimal GetTrustForNode(string nodeName)
    {
        return TransactionNodes.SingleOrDefault(n => n.Name == nodeName)?.TrustWeighting ?? 0m;
    }

    private bool IsSufficientlySyncedUp(string nodeName)
    {
        var ledgerTip = _latestLedgerTipByNode.GetValueOrDefault(nodeName);

        return ledgerTip != 0 &&
               (ledgerTip + Config.SufficientlySyncedStateVersionThreshold) > _knownTopOfCommittedLedger!.StateVersion;
    }

    private long? GetFirstStateVersionGapForNode(string nodeName, long stateVersionExclusiveLowerBound, long stateVersionInclusiveUpperBound)
    {
        var transactionsOnRecord = GetTransactionsForNode(nodeName);

        for (var stateVersion = stateVersionExclusiveLowerBound + 1; stateVersion <= stateVersionInclusiveUpperBound; stateVersion++)
        {
            if (!transactionsOnRecord.ContainsKey(stateVersion))
            {
                return stateVersion;
            }
        }

        return null;
    }

    private ConcurrentDictionary<long, CommittedTransaction> GetTransactionsForNode(string nodeName)
    {
        return _transactionsByNode.GetOrAdd(nodeName, new ConcurrentDictionary<long, CommittedTransaction>());
    }
}
