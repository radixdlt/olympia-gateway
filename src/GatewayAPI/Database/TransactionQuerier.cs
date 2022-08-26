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

using Common.Database.Models.Ledger;
using Common.Database.Models.Ledger.Normalization;
using Common.Database.Models.Mempool;
using Common.Extensions;
using Common.Numerics;
using Common.Utilities;
using GatewayAPI.ApiSurface;
using GatewayAPI.Services;
using Microsoft.EntityFrameworkCore;
using System.Runtime.Serialization;
using Gateway = RadixGatewayApi.Generated.Model;

namespace GatewayAPI.Database;

public interface ITransactionQuerier
{
    Task<TransactionPageWithoutTotal> GetRecentUserTransactions(RecentTransactionPageRequest request, Gateway.LedgerState atLedgerState, Gateway.LedgerState? fromLedgerState);

    Task<TransactionPageWithTotal> GetAccountTransactions(AccountTransactionPageRequest request, Gateway.LedgerState topLedgerState, Gateway.LedgerState? fromLedgerState);

    Task<Gateway.TransactionInfo?> LookupCommittedTransaction(
        ValidatedTransactionIdentifier transactionIdentifier,
        Gateway.LedgerState ledgerState
    );

    Task<Gateway.TransactionInfo?> LookupMempoolTransaction(
        ValidatedTransactionIdentifier transactionIdentifier
    );
}

[DataContract]
public record CommittedTransactionPaginationCursor(long? StateVersionBoundary)
{
    [DataMember(Name = "v", EmitDefaultValue = false)]
    public long? StateVersionBoundary { get; set; } = StateVersionBoundary;

    public static CommittedTransactionPaginationCursor? FromCursorString(string? cursorString)
    {
        return Serializations.FromBase64JsonOrDefault<CommittedTransactionPaginationCursor>(cursorString);
    }

    public string ToCursorString()
    {
        return Serializations.AsBase64Json(this);
    }
}

public record TransactionPageWithTotal(
    long TotalRecords,
    CommittedTransactionPaginationCursor? NextPageCursor,
    List<Gateway.TransactionInfo> Transactions
);

public record TransactionPageWithoutTotal(
    CommittedTransactionPaginationCursor? NextPageCursor,
    List<Gateway.TransactionInfo> Transactions
);

public record AccountTransactionPageRequest(
    ValidatedAccountAddress AccountAddress,
    CommittedTransactionPaginationCursor? Cursor,
    int PageSize
);

public record RecentTransactionPageRequest(
    CommittedTransactionPaginationCursor? Cursor,
    int PageSize
);

public class TransactionQuerier : ITransactionQuerier
{
    private readonly GatewayReadOnlyDbContext _dbContext;
    private readonly IDbContextFactory<GatewayReadOnlyDbContext> _dbContextFactory;
    private readonly ITokenQuerier _tokenQuerier;
    private readonly INetworkConfigurationProvider _networkConfigurationProvider;
    private readonly ISubmissionTrackingService _submissionTrackingService;

    public TransactionQuerier(
        GatewayReadOnlyDbContext dbContext,
        IDbContextFactory<GatewayReadOnlyDbContext> dbContextFactory,
        ITokenQuerier tokenQuerier,
        INetworkConfigurationProvider networkConfigurationProvider,
        ISubmissionTrackingService submissionTrackingService
    )
    {
        _dbContext = dbContext;
        _dbContextFactory = dbContextFactory;
        _tokenQuerier = tokenQuerier;
        _networkConfigurationProvider = networkConfigurationProvider;
        _submissionTrackingService = submissionTrackingService;
    }

    public async Task<TransactionPageWithoutTotal> GetRecentUserTransactions(RecentTransactionPageRequest request, Gateway.LedgerState atLedgerState, Gateway.LedgerState? fromLedgerState)
    {
        var transactionStateVersionsAndOneMore = await GetRecentUserTransactionStateVersions(request, atLedgerState, fromLedgerState);
        var nextCursor = transactionStateVersionsAndOneMore.Count == request.PageSize + 1
            ? new CommittedTransactionPaginationCursor(transactionStateVersionsAndOneMore.Last())
            : null;

        var transactions = await GetTransactions(
            transactionStateVersionsAndOneMore.Take(request.PageSize).ToList()
        );

        if (fromLedgerState != null)
        {
            transactions.Reverse();
        }

        return new TransactionPageWithoutTotal(nextCursor, transactions);
    }

    public async Task<TransactionPageWithTotal> GetAccountTransactions(AccountTransactionPageRequest request, Gateway.LedgerState atLedgerState, Gateway.LedgerState? fromLedgerState)
    {
        var totalCount = await CountAccountTransactions(request.AccountAddress, atLedgerState);
        var transactionStateVersionsAndOneMore = await GetAccountTransactionStateVersions(request, atLedgerState, fromLedgerState);
        var nextCursor = transactionStateVersionsAndOneMore.Count == request.PageSize + 1
            ? new CommittedTransactionPaginationCursor(transactionStateVersionsAndOneMore.Last())
            : null;

        var transactions = await GetTransactions(
            transactionStateVersionsAndOneMore.Take(request.PageSize).ToList()
        );

        if (fromLedgerState != null)
        {
            transactions.Reverse();
        }

        return new TransactionPageWithTotal(totalCount, nextCursor, transactions);
    }

    public async Task<Gateway.TransactionInfo?> LookupCommittedTransaction(
        ValidatedTransactionIdentifier transactionIdentifier,
        Gateway.LedgerState ledgerState
    )
    {
        var stateVersion = await _dbContext.LedgerTransactions
            .Where(lt =>
                lt.ResultantStateVersion <= ledgerState._Version
                && lt.TransactionIdentifierHash == transactionIdentifier.Bytes
            )
            .Select(lt => lt.ResultantStateVersion)
            .SingleOrDefaultAsync();

        return stateVersion == 0
            ? null :
            (await GetTransactions(new List<long> { stateVersion })).First();
    }

    public async Task<Gateway.TransactionInfo?> LookupMempoolTransaction(
        ValidatedTransactionIdentifier transactionIdentifier
    )
    {
        // We lookup the mempool transaction using the _submissionTrackingService which is bound to the
        // ReadWriteDbContext so that it gets the most recent details -- to ensure that submitted transactions
        // are immediately shown as pending.
        var mempoolTransaction = await _submissionTrackingService.GetMempoolTransaction(transactionIdentifier.Bytes);

        if (mempoolTransaction is null)
        {
            return null;
        }

        var transactionContents = mempoolTransaction.GetTransactionContents();

        var status = mempoolTransaction.Status switch
        {
            // If it is committed here, but not on ledger - it's likely because the read replica hasn't caught up yet
            MempoolTransactionStatus.Committed => new Gateway.TransactionStatus(
                Gateway.TransactionStatus.StatusEnum.CONFIRMED,
                transactionContents.ConfirmedTime?.AsUtcIsoDateWithMillisString(),
                transactionContents.LedgerStateVersion ?? 0
            ),
            MempoolTransactionStatus.SubmittedOrKnownInNodeMempool => new Gateway.TransactionStatus(Gateway.TransactionStatus.StatusEnum.PENDING),
            MempoolTransactionStatus.Missing => new Gateway.TransactionStatus(Gateway.TransactionStatus.StatusEnum.PENDING),
            MempoolTransactionStatus.ResolvedButUnknownTillSyncedUp => new Gateway.TransactionStatus(Gateway.TransactionStatus.StatusEnum.PENDING),
            MempoolTransactionStatus.Failed => new Gateway.TransactionStatus(Gateway.TransactionStatus.StatusEnum.FAILED),
            _ => throw new ArgumentOutOfRangeException(),
        };

        return new Gateway.TransactionInfo(
            status,
            new Gateway.TransactionIdentifier(mempoolTransaction.TransactionIdentifierHash.ToHex()),
            transactionContents.Actions,
            feePaid: TokenAmount.FromSubUnitsString(transactionContents.FeePaidSubunits).AsGatewayTokenAmount(_networkConfigurationProvider.GetXrdTokenIdentifier()),
            new Gateway.TransactionMetadata(
                hex: mempoolTransaction.Payload.ToHex(),
                message: transactionContents.MessageHex
            )
        );
    }

    private async Task<long> CountAccountTransactions(ValidatedAccountAddress accountAddress, Gateway.LedgerState ledgerState)
    {
        return await _dbContext.AccountTransactions
            .Where(at =>
                at.Account.Address == accountAddress.Address
                && at.ResultantStateVersion <= ledgerState._Version
                && !at.LedgerTransaction.IsStartOfEpoch
            )
            .CountAsync();
    }

    private async Task<List<long>> GetRecentUserTransactionStateVersions(RecentTransactionPageRequest request, Gateway.LedgerState atLedgerState, Gateway.LedgerState? fromLedgerState)
    {
        if (fromLedgerState != null)
        {
            var bottomStateVersionBoundary = request.Cursor?.StateVersionBoundary ?? fromLedgerState._Version;
            var topStateVersionBoundary = atLedgerState._Version;

            return await _dbContext.LedgerTransactions
                .Where(lt =>
                    lt.ResultantStateVersion >= bottomStateVersionBoundary && lt.ResultantStateVersion <= topStateVersionBoundary
                    && !lt.IsStartOfEpoch
                    && !lt.IsStartOfRound
                )
                .OrderBy(at => at.ResultantStateVersion)
                .Take(request.PageSize + 1)
                .Select(at => at.ResultantStateVersion)
                .ToListAsync();
        }
        else
        {
            var topStateVersionBoundary = request.Cursor?.StateVersionBoundary ?? atLedgerState._Version;

            return await _dbContext.LedgerTransactions
                .Where(lt =>
                    lt.ResultantStateVersion <= topStateVersionBoundary
                    && !lt.IsStartOfEpoch
                    && !lt.IsStartOfRound
                )
                .OrderByDescending(at => at.ResultantStateVersion)
                .Take(request.PageSize + 1)
                .Select(at => at.ResultantStateVersion)
                .ToListAsync();
        }
    }

    private async Task<List<long>> GetAccountTransactionStateVersions(AccountTransactionPageRequest request, Gateway.LedgerState atLedgerState, Gateway.LedgerState? fromLedgerState)
    {
        if (fromLedgerState != null)
        {
            var bottomStateVersionBoundary = request.Cursor?.StateVersionBoundary ?? fromLedgerState._Version;
            var topStateVersionBoundary = atLedgerState._Version;

            return await _dbContext.AccountTransactions
                .Where(at =>
                    at.Account.Address == request.AccountAddress.Address
                    && at.ResultantStateVersion >= bottomStateVersionBoundary && at.ResultantStateVersion <= topStateVersionBoundary
                    && !at.LedgerTransaction.IsStartOfEpoch
                )
                .OrderBy(at => at.ResultantStateVersion)
                .Take(request.PageSize + 1)
                .Select(at => at.ResultantStateVersion)
                .ToListAsync();
        }
        else
        {
            var topStateVersionBoundary = request.Cursor?.StateVersionBoundary ?? atLedgerState._Version;

            return await _dbContext.AccountTransactions
                .Where(at =>
                    at.Account.Address == request.AccountAddress.Address
                    && at.ResultantStateVersion <= topStateVersionBoundary
                    && !at.LedgerTransaction.IsStartOfEpoch
                )
                .OrderByDescending(at => at.ResultantStateVersion)
                .Take(request.PageSize + 1)
                .Select(at => at.ResultantStateVersion)
                .ToListAsync();
        }
    }

    private record JoinedStaticEntityLookup(
        Dictionary<long, Resource> Resources,
        Dictionary<long, Validator> Validators,
        Dictionary<long, Account> Accounts,
        Dictionary<byte[], RawTransaction> RawTransactions
    );

    private async Task<List<Gateway.TransactionInfo>> GetTransactions(List<long> transactionStateVersions)
    {
        async Task<List<LedgerTransaction>> LoadLedgerTransactions(List<long> ids)
        {
            await using var localCtx = await _dbContextFactory.CreateDbContextAsync();

            // we're using explicit transaction here to ensure that:
            // a) SET LOCAL call does not leak outside of this transaction
            // b) EF will actually reuse same database connection for both queries
            await using var tx = await localCtx.Database.BeginTransactionAsync();

            // query below tend to operate on quite significant volume of data (over 4 MiB)
            // so in order to prevent HDD/SSD usage while applying ORDER BY clause
            await localCtx.Database.ExecuteSqlRawAsync("SET LOCAL work_mem = '32MB';");

            var result = await localCtx.LedgerTransactions
                .Where(t => ids.Contains(t.ResultantStateVersion))
                .Include(t => t.SubstantiveOperationGroups)
                .OrderByDescending(lt => lt.ResultantStateVersion)
                .ToListAsync();

            await tx.CommitAsync();

            if (result.Count != ids.Count)
            {
                throw new Exception($"Expected {ids.Count} transactions, got {result.Count}. " +
                                    "This might be caused by replication-lag if you're using database cluster.");
            }

            return result;
        }

        async Task<Dictionary<long, Resource>> LoadResources(List<long> ids)
        {
            await using var localContext = await _dbContextFactory.CreateDbContextAsync();

            return await localContext.Resources.Where(r => ids.Contains(r.Id)).ToDictionaryAsync(r => r.Id);
        }

        async Task<Dictionary<long, Validator>> LoadValidators(List<long> ids)
        {
            await using var localContext = await _dbContextFactory.CreateDbContextAsync();

            return await localContext.Validators.Where(r => ids.Contains(r.Id)).ToDictionaryAsync(r => r.Id);
        }

        async Task<Dictionary<long, Account>> LoadAccounts(List<long> ids)
        {
            await using var localContext = await _dbContextFactory.CreateDbContextAsync();

            return await localContext.Accounts.Where(r => ids.Contains(r.Id)).ToDictionaryAsync(r => r.Id);
        }

        async Task<Dictionary<byte[], RawTransaction>> LoadRawTransactions(List<byte[]> ids)
        {
            await using var localContext = await _dbContextFactory.CreateDbContextAsync();

            return await localContext.RawTransactions.Where(r => ids.Contains(r.TransactionIdentifierHash)).ToDictionaryAsync(r => r.TransactionIdentifierHash, ByteArrayEqualityComparer.Default);
        }

        var transactionWithOperationGroups = await LoadLedgerTransactions(transactionStateVersions);

        // We used to operate on single query with joins but database/ef cost associated with ~10k rows
        // in result set was simply too big compared to this handcrafted entity construction.
        // EntityFramework generated not very performant queries (result of .AsSplitQuery()) under the hood.
        // What's more future version of this class will most likely cache ~99% of those resources in-memory.
        var resourceIds = new HashSet<long>();
        var validatorIds = new HashSet<long>();
        var fromAccountIds = new HashSet<long>();
        var toAccountIds = new HashSet<long>();
        var rawTransactionIds = new HashSet<byte[]>(ByteArrayEqualityComparer.Default);

        foreach (var transaction in transactionWithOperationGroups)
        {
            rawTransactionIds.Add(transaction.TransactionIdentifierHash);

            foreach (var operationGroup in transaction.SubstantiveOperationGroups)
            {
                if (operationGroup.InferredAction == null)
                {
                    continue;
                }

                resourceIds.Add(operationGroup.InferredAction.ResourceId ?? -1);
                validatorIds.Add(operationGroup.InferredAction.ValidatorId ?? -1);
                fromAccountIds.Add(operationGroup.InferredAction.FromAccountId ?? -1);
                toAccountIds.Add(operationGroup.InferredAction.ToAccountId ?? -1);
            }
        }

        var resourcesTask = LoadResources(resourceIds.Where(id => id > 0).ToList());
        var validatorsTask = LoadValidators(validatorIds.Where(id => id > 0).ToList());
        var accountsTask = LoadAccounts(fromAccountIds.Concat(toAccountIds).Where(id => id > 0).ToList());
        var rawTransactionsTask = LoadRawTransactions(rawTransactionIds.ToList());

        await Task.WhenAll(resourcesTask, validatorsTask, accountsTask, rawTransactionsTask);

        var entityLookup = new JoinedStaticEntityLookup(await resourcesTask, await validatorsTask, await accountsTask, await rawTransactionsTask);

        var gatewayTransactions = new List<Gateway.TransactionInfo>();
        foreach (var ledgerTransaction in transactionWithOperationGroups)
        {
            gatewayTransactions.Add(await MapToGatewayAccountTransaction(ledgerTransaction, entityLookup));
        }

        return gatewayTransactions;
    }

    private async Task<Gateway.TransactionInfo> MapToGatewayAccountTransaction(LedgerTransaction ledgerTransaction, JoinedStaticEntityLookup entityLookup)
    {
        var gatewayActions = new List<Gateway.Action>();

        foreach (var operationGroup in ledgerTransaction.SubstantiveOperationGroups)
        {
            var action = await GetAction(ledgerTransaction, operationGroup, entityLookup);
            if (action != null)
            {
                gatewayActions.Add(action);
            }
        }

        return new Gateway.TransactionInfo(
            new Gateway.TransactionStatus(
                Gateway.TransactionStatus.StatusEnum.CONFIRMED,
                confirmedTime: ledgerTransaction.RoundTimestamp.AsUtcIsoDateWithMillisString(),
                ledgerStateVersion: ledgerTransaction.ResultantStateVersion
            ),
            ledgerTransaction.TransactionIdentifierHash.AsGatewayTransactionIdentifier(),
            gatewayActions,
            ledgerTransaction.FeePaid.AsGatewayTokenAmount(_networkConfigurationProvider.GetXrdTokenIdentifier()),
            new Gateway.TransactionMetadata(
                hex: entityLookup.RawTransactions[ledgerTransaction.TransactionIdentifierHash].Payload.ToHex(),
                message: ledgerTransaction.Message?.ToHex()
            )
        );
    }

    private async Task<Gateway.Action?> GetAction(LedgerTransaction ledgerTransaction, LedgerOperationGroup operationGroup, JoinedStaticEntityLookup entityLookup)
    {
        var inferredAction = operationGroup.InferredAction;
        if (inferredAction?.Type == null)
        {
            return null;
        }

        // If necessary, we can improve this to prevent N+1 issues - but we expect CreatedTokenDefinitions to be rare
        async Task<Gateway.CreateTokenDefinition> GenerateCreateTokenDefinitionAction()
        {
            var createdTokenProperties = await _tokenQuerier.GetCreatedTokenProperties(entityLookup.Resources[inferredAction.ResourceId!.Value].ResourceIdentifier, operationGroup);
            return new Gateway.CreateTokenDefinition(
                tokenProperties: createdTokenProperties.TokenProperties,
                tokenSupply: createdTokenProperties.TokenSupply,
                toAccount: inferredAction.ToAccount?.AsGatewayAccountIdentifier()
            );
        }

        return inferredAction.Type switch
        {
            InferredActionType.CreateTokenDefinition => await GenerateCreateTokenDefinitionAction(),
            InferredActionType.SelfTransfer => new Gateway.TransferTokens(
                fromAccount: entityLookup.Accounts[inferredAction.FromAccountId!.Value].AsGatewayAccountIdentifier(),
                toAccount: entityLookup.Accounts[inferredAction.ToAccountId!.Value].AsGatewayAccountIdentifier(),
                amount: inferredAction.Amount!.Value.AsGatewayTokenAmount(entityLookup.Resources[inferredAction.ResourceId!.Value])
            ),
            InferredActionType.SimpleTransfer => new Gateway.TransferTokens(
                fromAccount: entityLookup.Accounts[inferredAction.FromAccountId!.Value].AsGatewayAccountIdentifier(),
                toAccount: entityLookup.Accounts[inferredAction.ToAccountId!.Value].AsGatewayAccountIdentifier(),
                amount: inferredAction.Amount!.Value.AsGatewayTokenAmount(entityLookup.Resources[inferredAction.ResourceId!.Value])
            ),
            InferredActionType.StakeTokens => new Gateway.StakeTokens(
                fromAccount: entityLookup.Accounts[inferredAction.FromAccountId!.Value].AsGatewayAccountIdentifier(),
                toValidator: entityLookup.Validators[inferredAction.ValidatorId!.Value].AsGatewayValidatorIdentifier(),
                amount: inferredAction.Amount!.Value.AsGatewayTokenAmount(entityLookup.Resources[inferredAction.ResourceId!.Value])
            ),
            InferredActionType.UnstakeTokens => new Gateway.UnstakeTokens(
                fromValidator: entityLookup.Validators[inferredAction.ValidatorId!.Value].AsGatewayValidatorIdentifier(),
                toAccount: entityLookup.Accounts[inferredAction.ToAccountId!.Value].AsGatewayAccountIdentifier(),
                amount: inferredAction.Amount!.Value.AsGatewayTokenAmount(entityLookup.Resources[inferredAction.ResourceId!.Value])
            ),
            InferredActionType.MintTokens => new Gateway.MintTokens(
                toAccount: entityLookup.Accounts[inferredAction.ToAccountId!.Value].AsGatewayAccountIdentifier(),
                amount: inferredAction.Amount!.Value.AsGatewayTokenAmount(entityLookup.Resources[inferredAction.ResourceId!.Value])
            ),
            InferredActionType.BurnTokens => new Gateway.BurnTokens(
                fromAccount: entityLookup.Accounts[inferredAction.FromAccountId!.Value].AsGatewayAccountIdentifier(),
                amount: inferredAction.Amount!.Value.AsGatewayTokenAmount(entityLookup.Resources[inferredAction.ResourceId!.Value])
            ),
            InferredActionType.MintXrd => new Gateway.MintTokens(
                toAccount: entityLookup.Accounts[inferredAction.ToAccountId!.Value].AsGatewayAccountIdentifier(),
                amount: inferredAction.Amount!.Value.AsGatewayTokenAmount(entityLookup.Resources[inferredAction.ResourceId!.Value])
            ),
            InferredActionType.PayXrd => inferredAction.Amount!.Value == ledgerTransaction.FeePaid
                ? null // Filter out fee payments
                : new Gateway.BurnTokens(
                    fromAccount: entityLookup.Accounts[inferredAction.FromAccountId!.Value].AsGatewayAccountIdentifier(),
                    amount: inferredAction.Amount!.Value.AsGatewayTokenAmount(entityLookup.Resources[inferredAction.ResourceId!.Value])
                ),
            InferredActionType.Complex => null,
            _ => throw new ArgumentOutOfRangeException(),
        };
    }
}
