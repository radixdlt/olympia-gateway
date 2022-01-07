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
using Common.Database.Models.Ledger.History;
using Common.Database.Models.Ledger.Joins;
using Common.Database.Models.Ledger.Normalization;
using Common.Database.Models.Ledger.Records;
using Common.Database.Models.Ledger.Substates;
using Common.Extensions;
using Common.Utilities;
using DataAggregator.DependencyInjection;
using DataAggregator.Exceptions;
using Microsoft.EntityFrameworkCore;
using InvalidTransactionException = DataAggregator.Exceptions.InvalidTransactionException;

namespace DataAggregator.LedgerExtension;

public record ActionsPlannerReport(
    long DbDependenciesLoadingMs,
    int ActionsCount,
    long LocalDbContextActionsMs
);

/// <summary>
/// When committing a ledger extension to the database, to keep this performant when doing a full sync, we need to
/// load dependencies for these transactions, and commit and DB ledger updates in batches.
///
/// This class forms the key to this batch processing.
///
/// First, for each transaction in the batch, a TransactionContentProcessor is created, which goes through the
/// transaction contents, and interacts with this class, in particular, it:
/// * Marks certain dependencies to be loaded in the dependency loading phase (and returns lookups which can be used
///   in the process actions phase for these dependencies)
/// * Adds deferred actions this class should be performed in the process actions phase.
///
/// The Actions Planner ProcessAllChanges() method then proceeds across a couple of key phases:
///
/// > Phase 1 - (Async) Loads dependencies
/// Referenced items on ledger (eg substates) and previous history values are loaded in batch into the DbContext.
/// These values are also loaded into local Dictionaries in this class, to act as local indexes - as reading off
/// of DbSet.Local is too slow.
///
/// > Phase 2 - Process Actions
/// The actions from the TransactionContentProcessor are processed in turn.
/// At this stage, the actions can make calls to any of the dependencies which were looked up earlier.
/// These actions add or mutate entities on the DbContext, and run suitable assertions on the ledger state.
/// The new items are added to the DbContext, and also to any local indexes, for use in later operations /
/// operation groups / transactions in the batch.
///
/// Not thread-safe - as per the dbContext it wraps.
/// </summary>
public class DbActionsPlanner
{
    private readonly AggregatorDbContext _dbContext;
    private readonly IEntityDeterminer _entityDeterminer;
    private readonly CancellationToken _cancellationToken;

    /** Things to load in the LoadDependencies step **/
    /* > Denormalized entities - the long is the first state version at which it appears */
    private readonly Dictionary<string, long> _resourcesToLoadOrCreate = new();
    private readonly Dictionary<string, long> _accountsToLoadOrCreate = new();
    private readonly Dictionary<string, long> _validatorsToLoadOrCreate = new();
    /* > Substates - by Substate Type and substate id */
    private readonly Dictionary<Type, HashSet<byte[]>> _substatesToLoad = new();
    /* > History Keys - to pull the latest history for that key */
    private readonly HashSet<AccountResourceDenormalized> _accountResourceHistoryToLoad = new();
    private readonly HashSet<string> _resourceSupplyHistoryToLoadByRri = new();
    private readonly HashSet<string> _validatorStakeHistoryToLoadByValidatorAddress = new();
    private readonly HashSet<AccountValidatorDenormalized> _accountValidatorStakeHistoryToLoad = new();
    /* > Records - pull the entry (if it exists) for upsertion */
    private readonly Dictionary<ValidatorEpochDenormalized, (ProposalRecord LatestData, long LatestStateVersion)> _latestSeenValidatorProposalRecords = new();

    /** Actions which will be performed in order in the ProcessActions step **/
    private readonly List<Action> _dbActions = new();

    /** Local DB Context indexes **/
    /* Initially I used DbSet<X>.Local, but it's too slow as it's unindexed - so store our own local indexes.
     * These should be null until they're created in the LoadDependencies step. */
    private readonly Dictionary<Type, Dictionary<byte[], SubstateBase>?> _localSubstates = new();
    private Dictionary<string, Resource>? _resourceLookupByRri;
    private Dictionary<string, Account>? _accountLookupByAddress;
    private Dictionary<string, Validator>? _validatorLookupByAddress;
    private Dictionary<AccountResource, AccountResourceBalanceHistory>? _latestAccountResourceHistory;
    private Dictionary<Resource, ResourceSupplyHistory>? _latestResourceSupplyHistory;
    private Dictionary<Validator, ValidatorStakeHistory>? _latestValidatorStakeHistory;
    private Dictionary<AccountValidator, AccountValidatorStakeHistory>? _latestAccountValidatorStakeHistory;

    public DbActionsPlanner(AggregatorDbContext dbContext, IEntityDeterminer entityDeterminer, CancellationToken cancellationToken)
    {
        _dbContext = dbContext;
        _entityDeterminer = entityDeterminer;
        _cancellationToken = cancellationToken;
    }

    public void AddDbAction(Action action)
    {
        _dbActions.Add(action);
    }

    public void UpSubstate<TSubstate>(
        TransactionOpLocator transactionOpLocator,
        byte[] identifier,
        Func<TSubstate> createNewSubstate,
        LedgerOperationGroup upOperationGroup,
        int upOperationIndexInGroup
    )
        where TSubstate : SubstateBase
    {
        MarkSubstateToLoadIfExists<TSubstate>(identifier);
        _dbActions.Add(() => UpSubstateFutureAction(transactionOpLocator, identifier, createNewSubstate, upOperationGroup, upOperationIndexInGroup));
    }

    public void DownSubstate<TSubstate>(
        TransactionOpLocator transactionOpLocator,
        byte[] identifier,
        Func<TSubstate> createNewSubstateIfVirtual,
        Func<TSubstate, bool> verifySubstateMatches,
        LedgerOperationGroup downOperationGroup,
        int downOperationIndexInGroup
    )
        where TSubstate : SubstateBase
    {
        MarkSubstateToLoadIfExists<TSubstate>(identifier);
        _dbActions.Add(() => DownSubstateFutureAction(transactionOpLocator, identifier, createNewSubstateIfVirtual, verifySubstateMatches, downOperationGroup, downOperationIndexInGroup));
    }

    /// <summary>
    /// Note that createNewHistoryFromPrevious does not need to care about the StateVersion.
    /// </summary>
    public void AddNewAccountResourceBalanceHistoryEntry(
        AccountResourceDenormalized historyKey,
        Func<AccountResourceBalanceHistory?, AccountResourceBalanceHistory> createNewHistoryFromPrevious,
        long transactionStateVersion
    )
    {
        _accountResourceHistoryToLoad.Add(historyKey);
        _dbActions.Add(() => AddNewHistoryEntryFutureAction(
            new AccountResource(GetLoadedAccount(historyKey.AccountAddress), GetLoadedResource(historyKey.Rri)),
            _latestAccountResourceHistory!,
            createNewHistoryFromPrevious,
            transactionStateVersion
        ));
    }

    /// <summary>
    /// Note that createNewHistoryFromPrevious does not need to care about the StateVersion.
    /// </summary>
    public void AddNewResourceSupplyHistoryEntry(
        string historyKey,
        Func<ResourceSupplyHistory?, ResourceSupplyHistory> createNewHistoryFromPrevious,
        long transactionStateVersion
    )
    {
        _resourceSupplyHistoryToLoadByRri.Add(historyKey);
        _dbActions.Add(() => AddNewHistoryEntryFutureAction(
            GetLoadedResource(historyKey),
            _latestResourceSupplyHistory!,
            createNewHistoryFromPrevious,
            transactionStateVersion
        ));
    }

    /// <summary>
    /// Note that createNewHistoryFromPrevious does not need to care about the StateVersion.
    /// </summary>
    public void AddNewValidatorStakeHistoryEntry(
        string historyKey,
        Func<ValidatorStakeHistory?, ValidatorStakeHistory> createNewHistoryFromPrevious,
        long transactionStateVersion
    )
    {
        _validatorStakeHistoryToLoadByValidatorAddress.Add(historyKey);
        _dbActions.Add(() => AddNewHistoryEntryFutureAction(
            GetLoadedValidator(historyKey),
            _latestValidatorStakeHistory!,
            createNewHistoryFromPrevious,
            transactionStateVersion
        ));
    }

    /// <summary>
    /// Note that createNewHistoryFromPrevious does not need to care about the StateVersion.
    /// </summary>
    public void AddNewAccountValidatorStakeHistoryEntry(
        AccountValidatorDenormalized historyKey,
        Func<AccountValidatorStakeHistory?, AccountValidatorStakeHistory> createNewHistoryFromPrevious,
        long transactionStateVersion
    )
    {
        _accountValidatorStakeHistoryToLoad.Add(historyKey);
        _dbActions.Add(() => AddNewHistoryEntryFutureAction(
            new AccountValidator(GetLoadedAccount(historyKey.AccountAddress), GetLoadedValidator(historyKey.ValidatorAddress)),
            _latestAccountValidatorStakeHistory!,
            createNewHistoryFromPrevious,
            transactionStateVersion
        ));
    }

    public void AddAccountTransactions(
        HashSet<string> accountAddresses,
        Func<Account?> resolveFeePayer,
        string? signerAccountAddress,
        long transactionStateVersion
    )
    {
        if (!accountAddresses.Any())
        {
            return;
        }

        accountAddresses.ToList().ForEach(accountAddress => EnsureAccountLoaded(accountAddress, transactionStateVersion));
        _dbActions.Add(() =>
        {
            var feePayer = resolveFeePayer();
            _dbContext.AccountTransactions.AddRange(accountAddresses.Select(
                accountAddress => new AccountTransaction
                {
                    Account = GetLoadedAccount(accountAddress),
                    ResultantStateVersion = transactionStateVersion,
                    IsFeePayer = feePayer == GetLoadedAccount(accountAddress),
                    IsSigner = signerAccountAddress == accountAddress,
                }
            ));
        });
    }

    /// <summary>
    /// Note that createNewHistoryFromPrevious does not need to care about the StateVersion.
    /// </summary>
    public void UpsertValidatorProposalRecord(
        ValidatorEpochDenormalized key,
        ProposalRecord latestData,
        long transactionStateVersion
    )
    {
        EnsureValidatorLoaded(key.ValidatorAddress, transactionStateVersion);
        _latestSeenValidatorProposalRecords[key] = (latestData, transactionStateVersion);
    }

    /// <summary>
    /// This registers that the resource needs to be loaded as a dependency, and returns a resource
    /// lookup which can be used in the action phase to resolve the Resource.
    /// </summary>
    public Func<Resource> ResolveResource(string resourceIdentifier, long seenAtStateVersion)
    {
        EnsureResourceLoaded(resourceIdentifier, seenAtStateVersion);
        return () => GetLoadedResource(resourceIdentifier);
    }

    /// <summary>
    /// This registers that the account needs to be loaded as a dependency, and returns an account
    /// lookup which can be used in the action phase to resolve the Account.
    /// </summary>
    public Func<Account> ResolveAccount(string accountAddress, long seenAtStateVersion)
    {
        EnsureAccountLoaded(accountAddress, seenAtStateVersion);
        return () => GetLoadedAccount(accountAddress);
    }

    /// <summary>
    /// This registers that the validator needs to be loaded as a dependency, and returns a validator
    /// lookup which can be used in the action phase to resolve the Validator.
    /// </summary>
    public Func<Validator> ResolveValidator(string validatorAddress, long seenAtStateVersion)
    {
        EnsureValidatorLoaded(validatorAddress, seenAtStateVersion);
        return () => GetLoadedValidator(validatorAddress);
    }

    public void MarkValidatorStakeHistoryToLoad(string validatorAddress)
    {
        _validatorStakeHistoryToLoadByValidatorAddress.Add(validatorAddress);
    }

    public async Task<ActionsPlannerReport> ProcessAllChanges()
    {
        var dbDependenciesLoadingMs = await CodeStopwatch.TimeInMs(LoadDependencies);
        var actionsCount = _dbActions.Count;
        var localDbContextActionsMs = CodeStopwatch.TimeInMs(RunActions);

        return new ActionsPlannerReport(dbDependenciesLoadingMs, actionsCount, localDbContextActionsMs);
    }

    /// <summary>
    /// This can only be called from the action phase (else it throws a null-ref).
    /// A call to this must have been pre-empted by a call to EnsureResourceLoaded in the dependencies phase.
    /// If this method throws, this is because the EnsureResourceLoaded call was forgotten.
    ///
    /// NB - The resource's id can be as 0, as the resource may not have actually been created yet.
    ///      So be sure to use the resource itself so EF Core can resolve the entity graph correctly upon save.
    /// </summary>
    public Resource GetLoadedResource(string resourceIdentifier)
    {
        return _resourceLookupByRri![resourceIdentifier];
    }

    /// <summary>
    /// This can only be called from the action phase (else it throws a null-ref).
    /// A call to this must have been pre-empted by a call to EnsureAccountLoaded in the dependencies phase.
    /// If this method throws, this is because the EnsureAccountLoaded call was forgotten.
    ///
    /// NB - The account's id can be as 0, as the account may not have actually been created yet.
    ///      So be sure to use the account itself so EF Core can resolve the entity graph correctly upon save.
    /// </summary>
    public Account GetLoadedAccount(string accountAddress)
    {
        return _accountLookupByAddress![accountAddress];
    }

    /// <summary>
    /// This can only be called from the action phase (else it throws a null-ref).
    /// A call to this must have been pre-empted by a call to EnsureValidatorLoaded in the dependencies phase.
    /// If this method throws, this is because the EnsureValidatorLoaded call was forgotten.
    ///
    /// NB - The validator's id can be as 0, as the validator may not have actually been created yet.
    ///      So be sure to use the validator itself so EF Core can resolve the entity graph correctly upon save.
    /// </summary>
    public Validator GetLoadedValidator(string validatorAddress)
    {
        return _validatorLookupByAddress![validatorAddress];
    }

    // NB - must be preceded by calls to MarkValidatorStakeHistoryToLoad
    public ValidatorStakeSnapshot GetLoadedLatestValidatorStakeSnapshot(string validatorAddress)
    {
        return _latestValidatorStakeHistory!.GetValueOrDefault(GetLoadedValidator(validatorAddress))?.StakeSnapshot
               ?? ValidatorStakeSnapshot.GetDefault();
    }

    /// <summary>
    /// Should only be used after Accounts have been fetched, so the lookup is local.
    /// </summary>
    private Account GetLoadedAccountById(long accountId)
    {
        return _dbContext.Set<Account>().Find(accountId)!;
    }

    private void EnsureAccountLoaded(string accountAddress, long seenAtStateVersion)
    {
        if (!_accountsToLoadOrCreate.ContainsKey(accountAddress))
        {
            _accountsToLoadOrCreate[accountAddress] = seenAtStateVersion;
        }
    }

    /// <summary>
    /// Should only be used after Resources have been fetched, so the lookup is local.
    /// </summary>
    private Resource GetLoadedResourceById(long resourceId)
    {
        return _dbContext.Set<Resource>().Find(resourceId)!;
    }

    private void EnsureResourceLoaded(string resourceIdentifier, long seenAtStateVersion)
    {
        if (!_resourcesToLoadOrCreate.ContainsKey(resourceIdentifier))
        {
            _resourcesToLoadOrCreate[resourceIdentifier] = seenAtStateVersion;
        }
    }

    /// <summary>
    /// Should only be used after Validators have been fetched, so the lookup is local.
    /// </summary>
    private Validator GetValidatorById(long validatorId)
    {
        return _dbContext.Set<Validator>().Find(validatorId)!;
    }

    private void EnsureValidatorLoaded(string validatorAddress, long seenAtStateVersion)
    {
        if (!_validatorsToLoadOrCreate.ContainsKey(validatorAddress))
        {
            _validatorsToLoadOrCreate[validatorAddress] = seenAtStateVersion;
        }
    }

    private async Task LoadDependencies()
    {
        await LoadOrCreateResources();
        await LoadOrCreateAccounts();
        await LoadOrCreateValidators();
        await LoadSubstatesOfType<AccountResourceBalanceSubstate>();
        await LoadSubstatesOfType<AccountStakeUnitBalanceSubstate>();
        await LoadSubstatesOfType<AccountXrdStakeBalanceSubstate>();
        await LoadSubstatesOfType<ValidatorStakeBalanceSubstate>();
        await LoadSubstatesOfType<ResourceDataSubstate>();
        await LoadSubstatesOfType<ValidatorDataSubstate>();
        await LoadAccountResourceBalanceHistoryEntries();
        await LoadResourceSupplyHistoryEntries();
        await LoadValidatorStakeHistoryEntries();
        await LoadAccountValidatorStakeHistoryEntries();
        await LoadValidatorProposalRecordsAndCreateActions();
    }

    private void RunActions()
    {
        foreach (var action in _dbActions)
        {
            action();
        }
    }

    private void MarkSubstateToLoadIfExists<TSubstate>(byte[] identifier)
        where TSubstate : SubstateBase
    {
        var substateIdentifiers = _substatesToLoad.GetOrCreate(typeof(TSubstate), () => new HashSet<byte[]>());
        substateIdentifiers.Add(identifier);
    }

    private void UpSubstateFutureAction<TSubstate>(
        TransactionOpLocator transactionOpLocator,
        byte[] identifier,
        Func<TSubstate> createNewSubstate,
        LedgerOperationGroup upOperationGroup,
        int upOperationIndexInGroup
    )
        where TSubstate : SubstateBase
    {
        var substates = _dbContext.Set<TSubstate>();
        var localSubstatesOfType = _localSubstates[typeof(TSubstate)]!;

        // Could rely on the database to check this constraint at commit time, but this gives us a clearer error
        var existingSubstate = localSubstatesOfType.GetValueOrDefault(identifier);
        if (existingSubstate != null)
        {
            throw new InvalidTransactionException(
                transactionOpLocator,
                $"{typeof(TSubstate).FullName} with identifier {identifier.ToHex()} can't be upped, as a substate of type {existingSubstate.GetType().Name} with that identifier already already exists in the database"
            );
        }

        var newSubstate = createNewSubstate();

        newSubstate.SubstateIdentifier = identifier;
        newSubstate.UpOperationGroup = upOperationGroup;
        newSubstate.UpOperationIndexInGroup = upOperationIndexInGroup;

        substates.Add(newSubstate);
        localSubstatesOfType.Add(identifier, newSubstate);
    }

    private void DownSubstateFutureAction<TSubstate>(
        TransactionOpLocator transactionOpLocator,
        byte[] identifier,
        Func<TSubstate> createNewSubstateIfVirtual,
        Func<TSubstate, bool> verifySubstateMatches,
        LedgerOperationGroup downOperationGroup,
        int downOperationIndexInGroup
    )
        where TSubstate : SubstateBase
    {
        var substates = _dbContext.Set<TSubstate>();
        var localSubstatesOfType = _localSubstates[typeof(TSubstate)]!;

        var untypedSubstate = localSubstatesOfType.GetValueOrDefault(identifier);
        if (untypedSubstate == null)
        {
            if (!SubstateBase.IsVirtualIdentifier(identifier))
            {
                throw new InvalidTransactionException(
                    transactionOpLocator,
                    $"Non-virtual {typeof(TSubstate).Name} with identifier {identifier.ToHex()} could not be downed as it did not exist in the database"
                );
            }

            // Virtual substates can be downed without being upped
            var newSubstate = createNewSubstateIfVirtual();
            newSubstate.SubstateIdentifier = identifier;
            newSubstate.UpOperationGroup = downOperationGroup;
            newSubstate.UpOperationIndexInGroup = downOperationIndexInGroup;
            newSubstate.DownOperationGroup = downOperationGroup;
            newSubstate.DownOperationIndexInGroup = downOperationIndexInGroup;
            substates.Add(newSubstate);
            localSubstatesOfType.Add(identifier, newSubstate);
            return;
        }

        if (untypedSubstate is not TSubstate substate)
        {
            throw new InvalidTransactionException(
                transactionOpLocator,
                $"{typeof(TSubstate).Name} with identifier {identifier.ToHex()} could not be downed as a substate of type {untypedSubstate.GetType().Name} was found with that identifier."
            );
        }

        if (substate.State == SubstateState.Down)
        {
            throw new InvalidTransactionException(
                transactionOpLocator,
                $"{typeof(TSubstate).Name} with identifier {identifier.ToHex()} could not be downed as it was already down"
            );
        }

        if (!verifySubstateMatches(substate))
        {
            throw new InvalidTransactionException(
                transactionOpLocator,
                $"{typeof(TSubstate).Name} with identifier {identifier.ToHex()} was downed, but the substate contents appear not to match at downing time"
            );
        }

        substate.DownOperationGroup = downOperationGroup;
        substate.DownOperationIndexInGroup = downOperationIndexInGroup;
    }

    private void AddNewHistoryEntryFutureAction<THistoryKey, THistory>(
        THistoryKey historyKey,
        Dictionary<THistoryKey, THistory> latestHistoryLookup,
        Func<THistory?, THistory> createNewHistoryFromPrevious,
        long transactionStateVersion
    )
        where THistory : HistoryBase
        where THistoryKey : notnull
    {
        var historyEntries = _dbContext.Set<THistory>();
        var existingHistoryItem = latestHistoryLookup.GetValueOrDefault(historyKey);

        if (existingHistoryItem == null)
        {
            var newHistoryItem = createNewHistoryFromPrevious(null);
            newHistoryItem.FromStateVersion = transactionStateVersion;
            historyEntries.Add(newHistoryItem);
            latestHistoryLookup[historyKey] = newHistoryItem;
        }
        else
        {
            var newHistoryItem = createNewHistoryFromPrevious(existingHistoryItem);
            existingHistoryItem.ToStateVersion = transactionStateVersion - 1;
            newHistoryItem.FromStateVersion = transactionStateVersion;
            historyEntries.Add(newHistoryItem);
            latestHistoryLookup[historyKey] = newHistoryItem;
        }
    }

    private void CreateRecordAction<TRecord>(
        TRecord newRecord,
        long lastTransactionStateVersion
    )
        where TRecord : RecordBase
    {
        newRecord.LastUpdatedAtStateVersion = lastTransactionStateVersion;
        _dbContext.Set<TRecord>().Add(newRecord);
    }

    private async Task LoadOrCreateResources()
    {
        if (_resourcesToLoadOrCreate.Count == 0)
        {
            return;
        }

        _resourceLookupByRri = await _dbContext.Set<Resource>()
            .Where(r => _resourcesToLoadOrCreate.Keys.Contains(r.ResourceIdentifier))
            .ToDictionaryAsync(
                resource => resource.ResourceIdentifier,
                _cancellationToken
            );

        foreach (var (rri, fromStateVersion) in _resourcesToLoadOrCreate)
        {
            if (_resourceLookupByRri.ContainsKey(rri))
            {
                continue;
            }

            var resource = new Resource
            {
                ResourceIdentifier = rri,
                RadixEngineAddress = _entityDeterminer.ParseResourceRadixEngineAddress(rri),
                FromStateVersion = fromStateVersion,
            };
            _dbContext.Set<Resource>().Add(resource);
            _resourceLookupByRri.Add(rri, resource);
        }
    }

    private async Task LoadOrCreateAccounts()
    {
        if (_accountsToLoadOrCreate.Count == 0)
        {
            return;
        }

        _accountLookupByAddress = await _dbContext.Set<Account>()
            .Where(a => _accountsToLoadOrCreate.Keys.Contains(a.Address))
            .ToDictionaryAsync(
                a => a.Address,
                _cancellationToken
            );

        foreach (var (accountAddress, fromStateVersion) in _accountsToLoadOrCreate)
        {
            if (_accountLookupByAddress.ContainsKey(accountAddress))
            {
                continue;
            }

            var account = new Account
            {
                Address = accountAddress,
                PublicKey = _entityDeterminer.ParseAccountPublicKey(accountAddress),
                FromStateVersion = fromStateVersion,
            };
            _dbContext.Set<Account>().Add(account);
            _accountLookupByAddress.Add(accountAddress, account);
        }
    }

    private async Task LoadOrCreateValidators()
    {
        if (_validatorsToLoadOrCreate.Count == 0)
        {
            return;
        }

        _validatorLookupByAddress = await _dbContext.Set<Validator>()
            .Where(v => _validatorsToLoadOrCreate.Keys.Contains(v.Address))
            .ToDictionaryAsync(
                v => v.Address,
                _cancellationToken
            );

        foreach (var (validatorAddress, fromStateVersion) in _validatorsToLoadOrCreate)
        {
            if (_validatorLookupByAddress.ContainsKey(validatorAddress))
            {
                continue;
            }

            var validator = new Validator
            {
                Address = validatorAddress,
                PublicKey = _entityDeterminer.ParseValidatorPublicKey(validatorAddress),
                FromStateVersion = fromStateVersion,
            };
            _dbContext.Set<Validator>().Add(validator);
            _validatorLookupByAddress.Add(validatorAddress, validator);
        }
    }

    private async Task LoadSubstatesOfType<TSubstate>()
        where TSubstate : SubstateBase
    {
        if (!_substatesToLoad.TryGetValue(typeof(TSubstate), out var identifiersToLoad))
        {
            return;
        }

        // TODO:NG-49 - If we hit limits - instead of doing a large "IN", we could consider using a Temporary Table for these loads
        //              For example - following in the footsteps of FromMultiDimensionalVirtualJoin
        var substates = await _dbContext.Set<TSubstate>()
            .Where(s => identifiersToLoad.Contains(s.SubstateIdentifier))
            .ToListAsync(_cancellationToken);

        var theseLocalSubstates = new Dictionary<byte[], SubstateBase>(ByteArrayEqualityComparer.Default);
        _localSubstates.Add(typeof(TSubstate), theseLocalSubstates);
        foreach (var substate in substates)
        {
            theseLocalSubstates.Add(substate.SubstateIdentifier, substate);
        }
    }

    private async Task LoadAccountResourceBalanceHistoryEntries()
    {
        if (!_accountResourceHistoryToLoad.Any())
        {
            return;
        }

        var dbKeys = new List<long>();
        foreach (var ar in _accountResourceHistoryToLoad)
        {
            var accountId = GetLoadedAccount(ar.AccountAddress).Id;
            var resourceId = GetLoadedResource(ar.Rri).Id;
            if (accountId == 0 || resourceId == 0)
            {
                // Account or Resource isn't yet in the database, so there can't be any history about them!
                continue;
            }

            dbKeys.Add(accountId);
            dbKeys.Add(resourceId);
        }

        if (!dbKeys.Any())
        {
            _latestAccountResourceHistory = new Dictionary<AccountResource, AccountResourceBalanceHistory>();
            return;
        }

        _latestAccountResourceHistory = await _dbContext.Set<AccountResourceBalanceHistory>()
            .FromMultiDimensionalVirtualJoin(
                "SELECT * FROM account_resource_balance_history",
                "(account_id, resource_id)",
                dbKeys.Cast<object>().ToArray(),
                2
            )
            .Where(t => t.ToStateVersion == null)
            .ToDictionaryAsync(
                ar => new AccountResource(GetLoadedAccountById(ar.AccountId), GetLoadedResourceById(ar.ResourceId)),
                _cancellationToken
            );
    }

    private async Task LoadResourceSupplyHistoryEntries()
    {
        if (!_resourceSupplyHistoryToLoadByRri.Any())
        {
            return;
        }

        var resourceIds = _resourceSupplyHistoryToLoadByRri
            .Select(rri => GetLoadedResource(rri).Id)
            .Where(id => id > 0)
            .ToList();

        if (!resourceIds.Any())
        {
            _latestResourceSupplyHistory = new Dictionary<Resource, ResourceSupplyHistory>();
            return;
        }

        _latestResourceSupplyHistory = await _dbContext.Set<ResourceSupplyHistory>()
            .Where(h => resourceIds.Contains(h.ResourceId) && h.ToStateVersion == null)
            .ToDictionaryAsync(
                h => GetLoadedResourceById(h.ResourceId),
                _cancellationToken
            );
    }

    private async Task LoadValidatorStakeHistoryEntries()
    {
        if (!_validatorStakeHistoryToLoadByValidatorAddress.Any())
        {
            return;
        }

        var validatorIds = _validatorStakeHistoryToLoadByValidatorAddress
            .Select(rri => GetLoadedValidator(rri).Id)
            .Where(id => id > 0)
            .ToList();

        if (!validatorIds.Any())
        {
            _latestValidatorStakeHistory = new Dictionary<Validator, ValidatorStakeHistory>();
            return;
        }

        _latestValidatorStakeHistory = await _dbContext.Set<ValidatorStakeHistory>()
            .Where(h => validatorIds.Contains(h.ValidatorId) && h.ToStateVersion == null)
            .ToDictionaryAsync(
                h => GetValidatorById(h.ValidatorId),
                _cancellationToken
            );
    }

    private async Task LoadAccountValidatorStakeHistoryEntries()
    {
        if (!_accountValidatorStakeHistoryToLoad.Any())
        {
            return;
        }

        var dbKeys = new List<long>();
        foreach (var av in _accountValidatorStakeHistoryToLoad)
        {
            var accountId = GetLoadedAccount(av.AccountAddress).Id;
            var validatorId = GetLoadedValidator(av.ValidatorAddress).Id;
            if (accountId == 0 || validatorId == 0)
            {
                // Account or Resource isn't yet in the database, so there can't be any history about them!
                continue;
            }

            dbKeys.Add(accountId);
            dbKeys.Add(validatorId);
        }

        if (!dbKeys.Any())
        {
            _latestAccountValidatorStakeHistory = new Dictionary<AccountValidator, AccountValidatorStakeHistory>();
            return;
        }

        _latestAccountValidatorStakeHistory = await _dbContext.Set<AccountValidatorStakeHistory>()
            .FromMultiDimensionalVirtualJoin(
                "SELECT * FROM account_validator_stake_history",
                "(account_id, validator_id)",
                dbKeys.Cast<object>().ToArray(),
                2
            )
            .Where(t => t.ToStateVersion == null)
            .ToDictionaryAsync(
                av => new AccountValidator(GetLoadedAccountById(av.AccountId), GetValidatorById(av.ValidatorId)),
                _cancellationToken
            );
    }

    private async Task LoadValidatorProposalRecordsAndCreateActions()
    {
        if (!_latestSeenValidatorProposalRecords.Any())
        {
            return;
        }

        var dbKeys = new List<long>();
        foreach (var (ve, _) in _latestSeenValidatorProposalRecords)
        {
            var validatorId = GetLoadedValidator(ve.ValidatorAddress).Id;
            if (validatorId == 0)
            {
                // Validator isn't yet in the database, so there can't be any records about them!
                continue;
            }

            dbKeys.Add(ve.Epoch);
            dbKeys.Add(validatorId);
        }

        var preExistingValidatorProposalRecords = dbKeys.Count == 0
        ? new Dictionary<ValidatorEpoch, ValidatorProposalRecord>()
        : await _dbContext.Set<ValidatorProposalRecord>()
            .FromMultiDimensionalVirtualJoin(
                "SELECT * FROM validator_proposal_records",
                "(epoch, validator_id)",
                dbKeys.Cast<object>().ToArray(),
                2
            )
            .ToDictionaryAsync(
                vpr => new ValidatorEpoch(GetValidatorById(vpr.ValidatorId), vpr.Epoch),
                _cancellationToken
            );

        foreach (var (ve, (latestData, latestStateVersion)) in _latestSeenValidatorProposalRecords)
        {
            var key = new ValidatorEpoch(GetLoadedValidator(ve.ValidatorAddress), ve.Epoch);
            var previousRecord = preExistingValidatorProposalRecords.GetValueOrDefault(key);
            if (previousRecord == null)
            {
                _dbActions.Add(() => CreateRecordAction(
                    new ValidatorProposalRecord(key, latestData), latestStateVersion
                ));
            }
            else
            {
                previousRecord.UpdateData(latestData);
                previousRecord.LastUpdatedAtStateVersion = latestStateVersion;
            }
        }
    }
}
