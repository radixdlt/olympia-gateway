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
using Common.Database.Models.Ledger;
using Common.Database.Models.SingleEntries;
using Common.Utilities;
using DataAggregator.DependencyInjection;
using DataAggregator.LedgerExtension;
using Microsoft.EntityFrameworkCore;
using NodaTime;

namespace DataAggregator.GlobalServices;

public interface ILedgerExtenderService
{
    Task<CommitTransactionsReport> CommitTransactions(
        ConsistentLedgerExtension ledgerExtension,
        SyncTarget latestSyncTarget,
        CancellationToken token
    );

    Task<TransactionSummary> GetTopOfLedger(CancellationToken token);
}

public record ConsistentLedgerExtension(
    TransactionSummary ParentSummary,
    List<CommittedTransactionData> TransactionData
);

public record CommitTransactionsReport(
    int TransactionsCommittedCount,
    TransactionSummary FinalTransaction,
    long RawTxnPersistenceMs,
    long MempoolTransactionUpdateMs,
    long TransactionContentHandlingMs,
    long DbDependenciesLoadingMs,
    int TransactionContentDbActionsCount,
    long LocalDbContextActionsMs,
    long DbPersistanceMs,
    int DbEntriesWritten
);

public class LedgerExtenderService : ILedgerExtenderService
{
    private readonly ILogger<LedgerExtenderService> _logger;
    private readonly IDbContextFactory<AggregatorDbContext> _dbContextFactory;
    private readonly IRawTransactionWriter _rawTransactionWriter;
    private readonly IEntityDeterminer _entityDeterminer;
    private readonly IActionInferrer _actionInferrer;
    private readonly INetworkConfigurationProvider _networkConfigurationProvider;

    private record ProcessTransactionReport(
        long TransactionContentHandlingMs,
        long DbDependenciesLoadingMs,
        int TransactionContentDbActionsCount,
        long LocalDbContextActionsMs
    );

    public LedgerExtenderService(
        ILogger<LedgerExtenderService> logger,
        IDbContextFactory<AggregatorDbContext> dbContextFactory,
        IRawTransactionWriter rawTransactionWriter,
        IEntityDeterminer entityDeterminer,
        IActionInferrer actionInferrer,
        INetworkConfigurationProvider networkConfigurationProvider
    )
    {
        _logger = logger;
        _dbContextFactory = dbContextFactory;
        _rawTransactionWriter = rawTransactionWriter;
        _entityDeterminer = entityDeterminer;
        _actionInferrer = actionInferrer;
        _networkConfigurationProvider = networkConfigurationProvider;
    }

    public async Task<TransactionSummary> GetTopOfLedger(CancellationToken token)
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(token);
        return await TransactionSummarisation.GetSummaryOfTransactionOnTopOfLedger(dbContext, token);
    }

    public async Task<CommitTransactionsReport> CommitTransactions(
        ConsistentLedgerExtension ledgerExtension,
        SyncTarget latestSyncTarget,
        CancellationToken token
    )
    {
        var preparationReport = await PrepareForLedgerExtension(ledgerExtension, token);

        var ledgerExtensionReport = await ExtendLedger(ledgerExtension, latestSyncTarget, token);
        var processTransactionReport = ledgerExtensionReport.ProcessTransactionReport;

        var dbEntriesWritten =
            preparationReport.RawTxnUpsertTouchedRecords
            + preparationReport.MempoolTransactionsTouchedRecords
            + preparationReport.PreparationEntriesTouched
            + ledgerExtensionReport.EntriesWritten;

        return new CommitTransactionsReport(
            ledgerExtension.TransactionData.Count,
            ledgerExtensionReport.FinalTransactionSummary,
            preparationReport.RawTxnPersistenceMs,
            preparationReport.MempoolTransactionUpdateMs,
            processTransactionReport.TransactionContentHandlingMs,
            processTransactionReport.DbDependenciesLoadingMs,
            processTransactionReport.TransactionContentDbActionsCount,
            processTransactionReport.LocalDbContextActionsMs,
            ledgerExtensionReport.DbPersistenceMs,
            dbEntriesWritten
        );
    }

    private record PreparationForLedgerExtensionReport(
        long RawTxnPersistenceMs,
        int RawTxnUpsertTouchedRecords,
        long MempoolTransactionUpdateMs,
        int MempoolTransactionsTouchedRecords,
        int PreparationEntriesTouched
    );

    /// <summary>
    ///  This should be idempotent - ie can be repeated if the main commit task fails.
    /// </summary>
    private async Task<PreparationForLedgerExtensionReport> PrepareForLedgerExtension(
        ConsistentLedgerExtension ledgerExtension,
        CancellationToken token
    )
    {
        await using var preparationDbContext = await _dbContextFactory.CreateDbContextAsync(token);

        var topOfLedgerSummary = await TransactionSummarisation.GetSummaryOfTransactionOnTopOfLedger(preparationDbContext, token);

        if (ledgerExtension.ParentSummary.StateVersion != topOfLedgerSummary.StateVersion)
        {
            throw new Exception(
                $"Tried to commit transactions with parent state version {ledgerExtension.ParentSummary.StateVersion} " +
                $"on top of a ledger with state version {topOfLedgerSummary.StateVersion}"
            );
        }

        if (topOfLedgerSummary.StateVersion == 0)
        {
            await EnsureDbLedgerIsInitialized(token);
        }

        var rawTransactions = ledgerExtension.TransactionData.Select(td => new RawTransaction(
            td.TransactionSummary.TransactionIdentifierHash,
            td.TransactionContents
        )).ToList();

        var (rawTransactionsTouched, rawTransactionCommitMs) = await CodeStopwatch.TimeInMs(
            () => _rawTransactionWriter.EnsureRawTransactionsCreatedOrUpdated(preparationDbContext, rawTransactions, token)
        );

        var (mempoolTransactionsTouched, mempoolTransactionUpdateMs) = await CodeStopwatch.TimeInMs(
            () => _rawTransactionWriter.EnsureMempoolTransactionsMarkedAsCommitted(preparationDbContext, ledgerExtension.TransactionData, token)
        );

        var preparationEntriesTouched = await preparationDbContext.SaveChangesAsync(token);

        return new PreparationForLedgerExtensionReport(
            rawTransactionCommitMs,
            rawTransactionsTouched,
            mempoolTransactionUpdateMs,
            mempoolTransactionsTouched,
            preparationEntriesTouched
        );
    }

    private async Task EnsureDbLedgerIsInitialized(CancellationToken token)
    {
        var created = await _networkConfigurationProvider.SaveLedgerNetworkConfigurationToDatabaseOnInitIfNotExists(token);
        if (created)
        {
            _logger.LogInformation(
                "Ledger initialized with network: {NetworkName}",
                _networkConfigurationProvider.GetNetworkName()
            );
        }
    }

    private record LedgerExtensionReport(
        ProcessTransactionReport ProcessTransactionReport,
        TransactionSummary FinalTransactionSummary,
        int EntriesWritten,
        long DbPersistenceMs
    );

    private async Task<LedgerExtensionReport> ExtendLedger(ConsistentLedgerExtension ledgerExtension, SyncTarget latestSyncTarget, CancellationToken token)
    {
        // Create own context for ledger extension unit of work
        await using var ledgerExtensionDbContext = await _dbContextFactory.CreateDbContextAsync(token);

        var processTransactionReport = await BulkProcessTransactionDependenciesAndEntityCreation(
            ledgerExtensionDbContext,
            ledgerExtension.TransactionData,
            token
        );

        var finalTransactionSummary = ledgerExtension.TransactionData.Last().TransactionSummary;

        await CreateOrUpdateLedgerStatus(ledgerExtensionDbContext, finalTransactionSummary, latestSyncTarget, token);

        var (ledgerExtensionEntriesWritten, dbPersistenceMs) = await CodeStopwatch.TimeInMs(
            () => ledgerExtensionDbContext.SaveChangesAsync(token)
        );

        return new LedgerExtensionReport(processTransactionReport, finalTransactionSummary, ledgerExtensionEntriesWritten, dbPersistenceMs);
    }

    private async Task<ProcessTransactionReport> BulkProcessTransactionDependenciesAndEntityCreation(
        AggregatorDbContext dbContext,
        List<CommittedTransactionData> transactions,
        CancellationToken cancellationToken
    )
    {
        var dbActionsPlanner = new DbActionsPlanner(dbContext, _entityDeterminer, cancellationToken);

        var transactionContentProcessingMs = CodeStopwatch.TimeInMs(
            () => ProcessTransactions(dbContext, dbActionsPlanner, transactions)
        );

        var dbActionsReport = await dbActionsPlanner.ProcessAllChanges();

        return new ProcessTransactionReport(
            transactionContentProcessingMs,
            dbActionsReport.DbDependenciesLoadingMs,
            dbActionsReport.ActionsCount,
            dbActionsReport.LocalDbContextActionsMs
        );
    }

    private void ProcessTransactions(AggregatorDbContext dbContext, DbActionsPlanner dbActionsPlanner, List<CommittedTransactionData> transactions)
    {
        foreach (var transactionData in transactions)
        {
            var dbTransaction = TransactionMapping.CreateLedgerTransaction(transactionData);
            dbContext.LedgerTransactions.Add(dbTransaction);

            var transactionContentProcessor = new TransactionContentProcessor(dbContext, dbActionsPlanner, _entityDeterminer, _actionInferrer);
            transactionContentProcessor.ProcessTransactionContents(transactionData.CommittedTransaction, dbTransaction, transactionData.TransactionSummary);
        }
    }

    private async Task CreateOrUpdateLedgerStatus(
        AggregatorDbContext dbContext,
        TransactionSummary finalTransactionSummary,
        SyncTarget latestSyncTarget,
        CancellationToken token
    )
    {
        var ledgerStatus = await dbContext.LedgerStatus.SingleOrDefaultAsync(token);

        if (ledgerStatus == null)
        {
            ledgerStatus = new LedgerStatus();
            dbContext.Add(ledgerStatus);
        }

        ledgerStatus.LastUpdated = SystemClock.Instance.GetCurrentInstant();
        ledgerStatus.TopOfLedgerStateVersion = finalTransactionSummary.StateVersion;
        ledgerStatus.SyncTarget = latestSyncTarget;
    }
}
