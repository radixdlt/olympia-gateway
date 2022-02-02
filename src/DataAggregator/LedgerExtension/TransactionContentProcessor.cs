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
using Common.Database.Models.Ledger.Normalization;
using Common.Database.Models.Ledger.Records;
using Common.Database.Models.Ledger.Substates;
using Common.Extensions;
using Common.Numerics;
using DataAggregator.DependencyInjection;
using DataAggregator.Exceptions;
using RadixCoreApi.Generated.Model;
using Api = RadixCoreApi.Generated.Model;
using Gateway = RadixGatewayApi.Generated.Model;
using InvalidTransactionException = DataAggregator.Exceptions.InvalidTransactionException;

namespace DataAggregator.LedgerExtension;

/// <summary>
/// A stateful class for processing the content of a transaction, and determining how the database should be updated.
/// The class is short-lived, lasting to process one transaction.
///
/// It works in tandem with the DbActionsPlanner, which is another stateful class, which lasts across the whole
/// batch of transactions, and is designed to enable performant bulk transaction processing.
///
/// Roughly, the process proceeds as follows:
/// * TransactionContentProcessor runs for each transaction, performing initial processing, which:
///   - Marks which dependencies need to be loaded / resolved
///   - Adds deferred "DbActions" against the DbActionsPlanner which will create/update entities on the DbContext
/// * DbActionsPlanner - Bulk load dependencies
/// * DbActionsPlanner - Process deferred actions in order
/// * DbContext is saved
///
/// See the DbActionsPlanner class doc for a detailed description on how this process should work.
/// </summary>
public class TransactionContentProcessor
{
    /* Dependencies */
    private readonly AggregatorDbContext _dbContext;
    private readonly DbActionsPlanner _dbActionsPlanner;
    private readonly IEntityDeterminer _entityDeterminer;
    private readonly IActionInferrer _actionInferrer;

    /* Tracked changes across the transaction to power history */
    private readonly Dictionary<AccountResourceDenormalized, TokenAmount> _accountResourceNetBalanceChanges = new();
    private readonly Dictionary<string, ResourceSupplyChange> _nonXrdResourceSupplyChangesAcrossOperationGroups = new();
    private readonly Dictionary<string, ValidatorStakeSnapshotChange> _validatorStakeChanges = new();
    private readonly Dictionary<AccountValidatorDenormalized, AccountValidatorStakeSnapshotChange> _accountValidatorStakeChanges = new();
    private readonly HashSet<string> _referencedAccountAddressesInTransaction = new();
    private Dictionary<string, TokenAmount> _nonXrdResourceChangeThisOperationGroupByRri = new();
    private TokenAmount _xrdResourceSupplyChange;

    /* Mutable Class State */
    /* > These simply help us avoid passing tons of references down the call stack.
    /* > These will all not be null at the time of use in the Handle methods. */
    private CommittedTransaction? _transaction;
    private TransactionSummary? _transactionSummary;
    private Account? _feePayer;
    private LedgerOperationGroup? _dbOperationGroup;
    private OperationGroup? _transactionOperationGroup;
    private int _operationGroupIndex = -1;
    private Operation? _operation;
    private int _operationIndexInGroup = -1;
    private Entity? _entity;
    private TokenAmount? _amount;

    public TransactionContentProcessor(
        AggregatorDbContext dbContext,
        DbActionsPlanner dbActionsPlanner,
        IEntityDeterminer entityDeterminer,
        IActionInferrer actionInferrer
    )
    {
        _dbContext = dbContext;
        _dbActionsPlanner = dbActionsPlanner;
        _entityDeterminer = entityDeterminer;
        _actionInferrer = actionInferrer;
    }

    public void ProcessTransactionContents(CommittedTransaction transaction, LedgerTransaction dbTransaction, TransactionSummary transactionSummary)
    {
        _transaction = transaction;
        _transactionSummary = transactionSummary;
        _operationGroupIndex = -1;
        foreach (var operationGroup in transaction.OperationGroups)
        {
            _operationGroupIndex++;
            _operationIndexInGroup = -1;
            _transactionOperationGroup = operationGroup;

            // Look for Validator Proposal updates -- before filtering out Operation Groups which just contain that or round data
            foreach (var operation in operationGroup.Operations)
            {
                _operationIndexInGroup += 1;
                if (!operation.IsCreateOf<ValidatorBFTData>(out var validatorBftData))
                {
                    continue;
                }

                _operation = operation;
                _entity = _entityDeterminer.DetermineEntity(_operation.EntityIdentifier);

                if (_entity == null)
                {
                    throw GenerateDetailedInvalidTransactionException(
                        $"Failed to identify the entity"
                    );
                }

                HandleValidatorBftDataOperationUp(validatorBftData);
            }

            // Only continue (to eg add a LedgerOperationGroup) if the content is substantive
            if (!operationGroup.HasOperationsOtherThanRoundDataOrValidatorBftData())
            {
                continue;
            }

            _dbOperationGroup = new LedgerOperationGroup(
                transaction.CommittedStateIdentifier.StateVersion,
                _operationGroupIndex,
                null // The inferred action calculated/set below in the dbAction after the transaction group has processed
            );
            _dbContext.OperationGroups.Add(_dbOperationGroup);
            _operationIndexInGroup = -1;
            AddDbActionToResolveInferredAction(
                GetCurrentTransactionOpLocator(),
                _actionInferrer.SummariseOperationGroup(operationGroup),
                dbTransaction,
                _dbOperationGroup
            );

            // Loop through again, processing all operations except RoundData and ValidatorBftData
            foreach (var operation in _transactionOperationGroup.Operations)
            {
                _operationIndexInGroup += 1;
                if (!operation.IsNotRoundDataOrValidatorBftData())
                {
                    continue;
                }

                _operation = operation;
                _entity = _entityDeterminer.DetermineEntity(_operation.EntityIdentifier);
                if (_entity == null)
                {
                    throw GenerateDetailedInvalidTransactionException(
                        $"Failed to identify the entity"
                    );
                }

                HandleOperation();

                _entity = null;
                _amount = null;
                _operation = null;
            }

            TrackNonXrdResourceSupplyChangesAcrossOperationGroup();
        }

        _dbOperationGroup = null;
        _transactionOperationGroup = null;
        _operationGroupIndex = -1;
        _operationIndexInGroup = -1;

        HandleHistoryUpdates();
        HandleAccountTransactions();
    }

    private void HandleValidatorBftDataOperationUp(ValidatorBFTData validatorBftData)
    {
        if (_entity!.EntityType != EntityType.Validator_System)
        {
            throw GenerateDetailedInvalidTransactionException(
                $"ValidatorBftData was against entity {_entity}, but a type of {EntityType.Validator_System} was expected."
            );
        }

        var validatorAddress = _entity!.ValidatorAddress!;

        _dbActionsPlanner.UpsertValidatorProposalRecord(
            new ValidatorEpochDenormalized(
                validatorAddress,
                _transactionSummary!.Epoch
            ),
            new ProposalRecord
            {
                ProposalsCompleted = validatorBftData.ProposalsCompleted,
                ProposalsMissed = validatorBftData.ProposalsMissed,
            },
            _transactionSummary.StateVersion
        );
    }

    private void HandleOperation()
    {
        if (_operation!.Amount != null)
        {
            HandleAmountOperation();
        }

        if (_operation!.Data != null)
        {
            HandleDataOperation();
        }
    }

    private void HandleAmountOperation()
    {
        _amount = TokenAmount.FromSubUnitsString(_operation!.Amount.Value);
        if (_amount.Value.IsNaN())
        {
            throw GenerateDetailedInvalidTransactionException(
                $"Unparsable token amount value: {_operation!.Amount.Value}"
            );
        }

        if (_entity!.AccountAddress != null)
        {
            // This captures all transactions where the entity or subentity is the relevant account, so it will
            // also capture start of epoch transactions where one of the stake subentities are involved.
            // EG epoch change transactions where a validator's owner account gets credited stake ownership
            _referencedAccountAddressesInTransaction.Add(_entity!.AccountAddress);
        }

        switch (_operation!.Amount.ResourceIdentifier)
        {
            case TokenResourceIdentifier resourceIdentifier:
                HandleResourceAmountOperation(resourceIdentifier);
                return;
            case StakeUnitResourceIdentifier stakeUnitResourceIdentifier:
                HandleStakeUnitAmountOperation(stakeUnitResourceIdentifier);
                return;
            default:
                throw GenerateDetailedInvalidTransactionException(
                    $"Unknown resource identifier type: {_operation!.Amount.ResourceIdentifier.Type}"
                );
        }
    }

    private void HandleResourceAmountOperation(TokenResourceIdentifier resourceIdentifier)
    {
        var rri = resourceIdentifier.Rri!;

        switch (_entity!.EntityType)
        {
            case EntityType.Account:
                HandleAccountResourceAmountOperation(_entity!.AccountAddress!, rri);
                break;
            case EntityType.Account_ExitingStake:
            case EntityType.Account_PreparedStake:
                HandleAccountXrdStakeResourceAmountOperation(_entity!, rri);
                break;
            case EntityType.Validator_System:
                HandleValidatorResourceAmountOperation(_entity!.ValidatorAddress!, rri);
                break;
            case EntityType.Account_PreparedUnstake:
            case EntityType.System:
            case EntityType.Validator:
            case EntityType.Resource:
            default:
                throw GenerateDetailedInvalidTransactionException(
                    $"Resource Amount operation against unsupported entity type: {_entity!.EntityType}"
                );
        }

        /* When tracking "totalMinted" and "totalBurned", we have to track slightly differently for XRD and other tokens.
         * For XRD, we sum up all operationGroups in a transaction, but for other tokens, we sum up per operationGroup.
         * This is because XRD fees can contain an initial "burn" and then a "mint" at the end of the transaction,
         * to get back unused gas. But these should be viewed as just a single "burn".
         * */
        if (_entityDeterminer.IsXrd(rri))
        {
            _xrdResourceSupplyChange += _amount!.Value;
        }
        else
        {
            var prevSupplyChange = _nonXrdResourceChangeThisOperationGroupByRri.GetValueOrDefault(rri);
            _nonXrdResourceChangeThisOperationGroupByRri[rri] = prevSupplyChange + _amount!.Value;
        }
    }

    private void HandleStakeUnitAmountOperation(StakeUnitResourceIdentifier stakeUnitResourceIdentifier)
    {
        switch (_entity!.EntityType)
        {
            case EntityType.Account:
            case EntityType.Account_PreparedUnstake:
                HandleAccountStakeUnitAmountOperation(_entity!.EntityType, _entity!.AccountAddress!, stakeUnitResourceIdentifier.ValidatorAddress);
                return;
            case EntityType.Account_ExitingStake:
            case EntityType.Account_PreparedStake:
            case EntityType.Validator_System:
            case EntityType.System:
            case EntityType.Validator:
            case EntityType.Resource:
            default:
                throw GenerateDetailedInvalidTransactionException(
                    $"Stake unit amount operation against unsupported entity type: {_entity!.EntityType}"
                );
        }
    }

    private void HandleAccountResourceAmountOperation(string accountAddress, string resourceIdentifier)
    {
        var tokenAmount = _amount!.Value;
        var accountLookup = _dbActionsPlanner.ResolveAccount(accountAddress, _transactionSummary!.StateVersion);
        var resourceLookup = _dbActionsPlanner.ResolveResource(resourceIdentifier, _transactionSummary!.StateVersion);

        // Part 1) Handle substates
        HandleSubstateUpOrDown(
            () => new AccountResourceBalanceSubstate(accountLookup(), resourceLookup(), tokenAmount),
            existingSubstate => (
                existingSubstate.Account == accountLookup()
                && existingSubstate.Resource == resourceLookup()
                && existingSubstate.Amount == -tokenAmount // Negative because downed has the opposite amount as upped
            )
        );

        // Part 2) Handle history
        _accountResourceNetBalanceChanges.TrackBalanceDelta(new AccountResourceDenormalized(accountAddress, resourceIdentifier), TokenAmount.FromSubUnitsString(_operation!.Amount.Value));
    }

    private void HandleAccountXrdStakeResourceAmountOperation(Entity entity, string resourceIdentifier)
    {
        var tokenAmount = _amount!.Value;
        var accountAddress = entity.AccountAddress!;
        var validatorAddress = entity.ValidatorAddress!;

        if (!_entityDeterminer.IsXrd(resourceIdentifier))
        {
            throw GenerateDetailedInvalidTransactionException(
                $"Resource Amount operation against unsupported entity type: {_entity!.EntityType}"
            );
        }

        var type = entity.EntityType! switch
        {
            EntityType.Account_PreparedStake => AccountXrdStakeBalanceSubstateType.PreparedStake,
            EntityType.Account_ExitingStake => AccountXrdStakeBalanceSubstateType.ExitingStake,
            _ => throw new ArgumentOutOfRangeException(),
        };

        var accountLookup = _dbActionsPlanner.ResolveAccount(accountAddress, _transactionSummary!.StateVersion);
        var validatorLookup = _dbActionsPlanner.ResolveValidator(validatorAddress, _transactionSummary!.StateVersion);

        // Part 1) Handle substates
        HandleSubstateUpOrDown(
            () => new AccountXrdStakeBalanceSubstate(
                accountLookup(),
                validatorLookup(),
                type,
                entity.EpochUnlock,
                tokenAmount
            ),
            existingSubstate => (
                existingSubstate.Account == accountLookup()
                && existingSubstate.Validator == validatorLookup()
                && existingSubstate.Type == type
                && existingSubstate.UnlockEpoch == entity.EpochUnlock
                && existingSubstate.Amount == -tokenAmount // Negative because downed has the opposite amount as upped
            )
        );

        // Part 2) Handle history
        var preValidatorStake = _validatorStakeChanges.GetOrCreate(validatorAddress, ValidatorStakeSnapshotChange.Default);
        var preAccountValidatorStake = _accountValidatorStakeChanges.GetOrCreate(
            new AccountValidatorDenormalized(accountAddress, validatorAddress), AccountValidatorStakeSnapshotChange.Default
        );

        switch (entity.EntityType!)
        {
            case EntityType.Account_PreparedStake:
                preValidatorStake.AggregatePreparedXrdStakeChange(tokenAmount);
                preAccountValidatorStake.AggregatePreparedXrdStakeChange(tokenAmount);
                break;
            case EntityType.Account_ExitingStake:
                preValidatorStake.AggregateChangeInExitingXrdStakeChange(tokenAmount);
                preAccountValidatorStake.AggregateChangeInExitingXrdStakeChange(tokenAmount);
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    private void HandleValidatorResourceAmountOperation(string validatorAddress, string resourceIdentifier)
    {
        var tokenAmount = _amount!.Value;

        if (!_entityDeterminer.IsXrd(resourceIdentifier))
        {
            throw GenerateDetailedInvalidTransactionException(
                $"Resource Amount operation against unsupported entity type: {_entity!.EntityType}"
            );
        }

        var validatorLookup = _dbActionsPlanner.ResolveValidator(validatorAddress, _transactionSummary!.StateVersion);

        // Part 1) Handle substates
        HandleSubstateUpOrDown(
            () => new ValidatorStakeBalanceSubstate(
                validatorLookup(),
                _transactionSummary!.Epoch, // Put in for history's sake, but not part of the substate, so shouldn't be verified against
                tokenAmount
            ),
            existingSubstate => (
                existingSubstate.Validator == validatorLookup()
                && existingSubstate.Amount == -tokenAmount // Negative because downed has the opposite amount as upped
            )
        );

        // Part 2) Handle history
        _validatorStakeChanges.GetOrCreate(validatorAddress, ValidatorStakeSnapshotChange.Default).AggregateXrdStakeChange(tokenAmount);
    }

    private void HandleAccountStakeUnitAmountOperation(EntityType entityType, string accountAddress, string validatorAddress)
    {
        var tokenAmount = _amount!.Value;

        if (entityType == EntityType.Account_PreparedUnstake)
        {
            // This is to enable the action inference to calculate the XRD
            _dbActionsPlanner.MarkValidatorStakeHistoryToLoad(validatorAddress);
        }

        var type = entityType switch
        {
            EntityType.Account => AccountStakeUnitBalanceSubstateType.Stake,
            EntityType.Account_PreparedUnstake => AccountStakeUnitBalanceSubstateType.PreparedUnstake,
            _ => throw new ArgumentOutOfRangeException(),
        };

        var accountLookup = _dbActionsPlanner.ResolveAccount(accountAddress, _transactionSummary!.StateVersion);
        var validatorLookup = _dbActionsPlanner.ResolveValidator(validatorAddress, _transactionSummary!.StateVersion);

        // Part 1) Handle substates
        HandleSubstateUpOrDown(
            () => new AccountStakeUnitBalanceSubstate(
                accountLookup(),
                validatorLookup(),
                type,
                tokenAmount
            ),
            existingSubstate => (
                existingSubstate.Account == accountLookup()
                && existingSubstate.Validator == validatorLookup()
                && existingSubstate.Type == type
                && existingSubstate.Amount == -tokenAmount // Negative because downed has the opposite amount as upped
            )
        );

        // Part 2) Handle history
        var preValidatorStake = _validatorStakeChanges.GetOrCreate(validatorAddress, ValidatorStakeSnapshotChange.Default);
        var preAccountValidatorStake = _accountValidatorStakeChanges.GetOrCreate(
            new AccountValidatorDenormalized(accountAddress, validatorAddress), AccountValidatorStakeSnapshotChange.Default
        );

        switch (entityType)
        {
            case EntityType.Account:
                preValidatorStake.AggregateStakeUnitChange(tokenAmount);
                preAccountValidatorStake.AggregateStakeUnitChange(tokenAmount);
                break;
            case EntityType.Account_PreparedUnstake:
                preValidatorStake.AggregatePreparedUnStakeUnitChange(tokenAmount);
                preAccountValidatorStake.AggregatePreparedUnStakeUnitChange(tokenAmount);
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    private void HandleDataOperation()
    {
        switch (_operation!.Data.DataObject)
        {
            case Api.TokenData tokenData:
                HandleResourceDataOperation(new ResourceDataObjects { TokenData = tokenData });
                return;
            case Api.TokenMetadata tokenMetadata:
                HandleResourceDataOperation(new ResourceDataObjects { TokenMetadata = tokenMetadata });
                return;
            case Api.ValidatorData validatorData:
                HandleValidatorDataOperation(new ValidatorDataObjects { ValidatorData = validatorData });
                return;
            case Api.ValidatorMetadata validatorMetadata:
                HandleValidatorDataOperation(new ValidatorDataObjects { ValidatorMetadata = validatorMetadata });
                return;
            case Api.ValidatorAllowDelegation validatorAllowDelegation:
                HandleValidatorDataOperation(new ValidatorDataObjects { ValidatorAllowDelegation = validatorAllowDelegation });
                return;
            case Api.PreparedValidatorRegistered preparedValidatorRegistered:
                HandleValidatorDataOperation(new ValidatorDataObjects { PreparedValidatorRegistered = preparedValidatorRegistered });
                return;
            case Api.PreparedValidatorFee preparedValidatorFee:
                HandleValidatorDataOperation(new ValidatorDataObjects { PreparedValidatorFee = preparedValidatorFee });
                return;
            case Api.PreparedValidatorOwner preparedValidatorOwner:
                HandleValidatorDataOperation(new ValidatorDataObjects { PreparedValidatorOwner = preparedValidatorOwner });
                return;
            default:
                // Don't handle other data types for now
                return;
        }
    }

    private void HandleResourceDataOperation(ResourceDataObjects objects)
    {
        if (_entity!.EntityType != EntityType.Resource)
        {
            throw GenerateDetailedInvalidTransactionException("Resource data update not against a resource entity");
        }

        var resourceIdentifier = _entity.ResourceAddress!;
        var resourceLookup = _dbActionsPlanner.ResolveResource(resourceIdentifier, _transactionSummary!.StateVersion);
        var resourceOwnerLookup = CreateAccountLookup(objects.TokenData?.Owner);

        HandleSubstateUpOrDown(
            () => objects.ToResourceDataSubstate(resourceLookup(), resourceOwnerLookup?.Invoke()),
            existingSubstate => existingSubstate.SubstateMatches(
                objects.ToResourceDataSubstate(resourceLookup(), resourceOwnerLookup?.Invoke())
            )
        );
    }

    private void HandleValidatorDataOperation(ValidatorDataObjects objects)
    {
        if (_entity!.EntityType != EntityType.Validator && _entity!.EntityType != EntityType.Validator_System)
        {
            throw GenerateDetailedInvalidTransactionException("Validator data update not against validator or validator__system entity");
        }

        var validatorLookup = _dbActionsPlanner.ResolveValidator(_entity.ValidatorAddress!, _transactionSummary!.StateVersion);
        var validatorOwnerLookup = CreateAccountLookup(objects.PreparedValidatorOwner?.Owner ?? objects.ValidatorData?.Owner);

        HandleSubstateUpOrDown(
            () => objects.ToDbValidatorData(validatorLookup(), validatorOwnerLookup?.Invoke()),
            existingSubstate => existingSubstate.SubstateMatches(
                objects.ToDbValidatorData(validatorLookup(), validatorOwnerLookup?.Invoke())
            )
        );
    }

    private Func<Account>? CreateAccountLookup(EntityIdentifier? identifier)
    {
        if (identifier == null)
        {
            return null;
        }

        var entity = _entityDeterminer.DetermineEntity(identifier);
        if (entity is not { EntityType: EntityType.Account })
        {
            throw GenerateDetailedInvalidTransactionException("Resource data update not against a resource entity");
        }

        return _dbActionsPlanner.ResolveAccount(entity.AccountAddress!, _transactionSummary!.StateVersion);
    }

    private void TrackNonXrdResourceSupplyChangesAcrossOperationGroup()
    {
        foreach (var (rri, change) in _nonXrdResourceChangeThisOperationGroupByRri)
        {
            if (change.IsZero())
            {
                continue;
            }

            _nonXrdResourceSupplyChangesAcrossOperationGroups.GetOrCreate(rri, ResourceSupplyChange.Default).Aggregate(change);
        }

        // Prepare for next operation group
        _nonXrdResourceChangeThisOperationGroupByRri = new Dictionary<string, TokenAmount>();
    }

    private void HandleHistoryUpdates()
    {
        HandleAccountResourceBalanceHistoryUpdates();
        HandleResourceSupplyHistoryUpdates();
        HandleValidatorStakeHistoryUpdates();
        HandleAccountValidatorStakeHistoryUpdates();
    }

    private void HandleAccountResourceBalanceHistoryUpdates()
    {
        var accountResourceHistoryChanges = _accountResourceNetBalanceChanges
            .Where(arnb => arnb.Value != TokenAmount.Zero);

        foreach (var (key, entry) in accountResourceHistoryChanges)
        {
            if (entry.IsNaN())
            {
                throw GenerateDetailedInvalidTransactionException($"Balance delta calculated for account resource {key} is NaN");
            }

            var accountLookup = _dbActionsPlanner.ResolveAccount(key.AccountAddress, _transactionSummary!.StateVersion);
            var resourceLookup = _dbActionsPlanner.ResolveResource(key.Rri, _transactionSummary!.StateVersion);
            _dbActionsPlanner.AddNewAccountResourceBalanceHistoryEntry(
                key,
                oldHistory =>
                {
                    var normalizedKey = new AccountResource(accountLookup(), resourceLookup());
                    var newHistoryEntry = AccountResourceBalanceHistory.FromPreviousEntry(normalizedKey, oldHistory?.BalanceEntry, entry);
                    if (newHistoryEntry.BalanceEntry.Balance.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} balance ended up negative: {newHistoryEntry.BalanceEntry}");
                    }

                    return newHistoryEntry;
                },
                _transactionSummary!.StateVersion
            );
        }
    }

    private void HandleResourceSupplyHistoryUpdates()
    {
        var totalResourceChanges = _xrdResourceSupplyChange.IsZero()
            ? _nonXrdResourceSupplyChangesAcrossOperationGroups
            : _nonXrdResourceSupplyChangesAcrossOperationGroups.Concat(new KeyValuePair<string, ResourceSupplyChange>[]
                {
                    new(_entityDeterminer.GetXrdAddress(), ResourceSupplyChange.From(_xrdResourceSupplyChange)),
                }
            );

        foreach (var (key, supplyChange) in totalResourceChanges)
        {
            if (supplyChange.Minted.IsNaN() || supplyChange.Burned.IsNaN())
            {
                throw GenerateDetailedInvalidTransactionException($"Resource supply Minted or Burned delta calculated for resource {key} is NaN");
            }

            if (supplyChange.Minted.IsZero() && supplyChange.Burned.IsZero())
            {
                throw GenerateDetailedInvalidTransactionException($"Calculation gone wrong - resource supply change was tracked, but Minted and Burned delta were both zero for resource {key}");
            }

            var resourceLookup = _dbActionsPlanner.ResolveResource(key, _transactionSummary!.StateVersion);
            _dbActionsPlanner.AddNewResourceSupplyHistoryEntry(
                key,
                oldHistory =>
                {
                    var newHistoryEntry = ResourceSupplyHistory.FromPreviousEntry(resourceLookup(), oldHistory?.ResourceSupply, supplyChange);
                    if (newHistoryEntry.ResourceSupply.TotalSupply.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} TotalSupply ended up negative: {newHistoryEntry.ResourceSupply.TotalSupply}");
                    }

                    return newHistoryEntry;
                },
                _transactionSummary!.StateVersion
            );
        }
    }

    private void HandleValidatorStakeHistoryUpdates()
    {
        var validatorStakeChanges = _validatorStakeChanges
            .Where(kvp => kvp.Value.IsMeaningfulChange());

        foreach (var (key, stakeSnapshotChange) in validatorStakeChanges)
        {
            if (stakeSnapshotChange.IsNaN())
            {
                throw GenerateDetailedInvalidTransactionException($"Validator stake snapshot change for validator {key} had a NaN value");
            }

            var validatorLookup = _dbActionsPlanner.ResolveValidator(key, _transactionSummary!.StateVersion);

            _dbActionsPlanner.AddNewValidatorStakeHistoryEntry(
                key,
                oldHistory =>
                {
                    var newHistoryEntry = ValidatorStakeHistory.FromPreviousEntry(validatorLookup(), oldHistory?.StakeSnapshot, stakeSnapshotChange);
                    if (newHistoryEntry.StakeSnapshot.TotalXrdStake.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} TotalXrdStake ended up negative: {newHistoryEntry.StakeSnapshot.TotalXrdStake}");
                    }

                    if (newHistoryEntry.StakeSnapshot.TotalStakeUnits.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} TotalStakeUnit ended up negative: {newHistoryEntry.StakeSnapshot.TotalStakeUnits}");
                    }

                    if (newHistoryEntry.StakeSnapshot.TotalPreparedXrdStake.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} TotalPreparedXrdStake ended up negative: {newHistoryEntry.StakeSnapshot.TotalPreparedXrdStake}");
                    }

                    if (newHistoryEntry.StakeSnapshot.TotalPreparedUnStakeUnits.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} TotalPreparedUnStakeUnit ended up negative: {newHistoryEntry.StakeSnapshot.TotalPreparedUnStakeUnits}");
                    }

                    if (newHistoryEntry.StakeSnapshot.TotalExitingXrdStake.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} TotalExitingXrdStake ended up negative: {newHistoryEntry.StakeSnapshot.TotalExitingXrdStake}");
                    }

                    return newHistoryEntry;
                },
                _transactionSummary!.StateVersion
            );
        }
    }

    private void HandleAccountValidatorStakeHistoryUpdates()
    {
        var accountValidatorStakeChanges = _accountValidatorStakeChanges
            .Where(kvp => kvp.Value.IsMeaningfulChange());

        foreach (var (key, stakeSnapshotChange) in accountValidatorStakeChanges)
        {
            if (stakeSnapshotChange.IsNaN())
            {
                throw GenerateDetailedInvalidTransactionException($"Account Validator stake snapshot change for validator {key} had a NaN value");
            }

            var accountLookup = _dbActionsPlanner.ResolveAccount(key.AccountAddress, _transactionSummary!.StateVersion);
            var validatorLookup = _dbActionsPlanner.ResolveValidator(key.ValidatorAddress, _transactionSummary!.StateVersion);

            _dbActionsPlanner.AddNewAccountValidatorStakeHistoryEntry(
                key,
                oldHistory =>
                {
                    var newHistoryEntry = AccountValidatorStakeHistory.FromPreviousEntry(
                         new AccountValidator(accountLookup(), validatorLookup()),
                         oldHistory?.StakeSnapshot,
                         stakeSnapshotChange
                    );

                    if (newHistoryEntry.StakeSnapshot.TotalStakeUnits.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} TotalStakeUnit ended up negative: {newHistoryEntry.StakeSnapshot.TotalStakeUnits}");
                    }

                    if (newHistoryEntry.StakeSnapshot.TotalPreparedXrdStake.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} TotalPreparedXrdStake ended up negative: {newHistoryEntry.StakeSnapshot.TotalPreparedXrdStake}");
                    }

                    if (newHistoryEntry.StakeSnapshot.TotalPreparedUnStakeUnits.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} TotalPreparedUnStakeUnit ended up negative: {newHistoryEntry.StakeSnapshot.TotalPreparedUnStakeUnits}");
                    }

                    if (newHistoryEntry.StakeSnapshot.TotalExitingXrdStake.IsNegative())
                    {
                        throw GenerateDetailedInvalidTransactionException($"{key} TotalExitingXrdStake ended up negative: {newHistoryEntry.StakeSnapshot.TotalExitingXrdStake}");
                    }

                    return newHistoryEntry;
                },
                _transactionSummary!.StateVersion
            );
        }
    }

    // We put this in a method to ensure we capture these arguments in a closure
    private void AddDbActionToResolveInferredAction(
        TransactionOpLocator transactionOpLocator,
        OperationGroupSummarisation operationGroupSummarisation,
        LedgerTransaction dbTransaction,
        LedgerOperationGroup dbOperationGroup
    )
    {
        _dbActionsPlanner.AddDbAction(() =>
        {
            var inferredAction = CalculateInferredAction(
                transactionOpLocator,
                dbTransaction.IsSystemTransaction,
                operationGroupSummarisation
            );

            dbOperationGroup.InferredAction = inferredAction;

            // ReSharper disable once InvertIf - it's clearer like this
            if (inferredAction is { Type: InferredActionType.PayXrd })
            {
                if (_feePayer != null)
                {
                    throw new InvalidTransactionException(transactionOpLocator, "Transaction had two pay xrd actions");
                }

                _feePayer = inferredAction.FromAccount!;
            }
        });
    }

    private InferredAction? CalculateInferredAction(
        TransactionOpLocator transactionOpLocator,
        bool isSystemTransaction,
        OperationGroupSummarisation summarisation
    )
    {
        try
        {
            var inferredGatewayAction = _actionInferrer.InferAction(
                isSystemTransaction,
                summarisation,
                _dbActionsPlanner.GetLoadedLatestValidatorStakeSnapshot
            );

            return inferredGatewayAction switch
            {
                null => null,
                { Type: InferredActionType.Complex } => InferredAction.Complex(),
                { Type: InferredActionType.CreateTokenDefinition, Action: Gateway.CreateTokenDefinition action } => new InferredAction(
                    inferredGatewayAction.Type,
                    fromAccount: null,
                    toAccount: action.ToAccount != null ? _dbActionsPlanner.GetLoadedAccount(action.ToAccount.Address) : null,
                    validator: null,
                    amount: TokenAmount.FromSubUnitsString(action.TokenSupply.Value),
                    resource: _dbActionsPlanner.GetLoadedResource(action.TokenSupply.TokenIdentifier.Rri)
                ),
                { Type: InferredActionType.MintTokens or InferredActionType.MintXrd, Action: Gateway.MintTokens action } => new InferredAction(
                    inferredGatewayAction.Type,
                    fromAccount: null,
                    toAccount: _dbActionsPlanner.GetLoadedAccount(action.ToAccount.Address),
                    validator: null,
                    amount: TokenAmount.FromSubUnitsString(action.Amount.Value),
                    resource: _dbActionsPlanner.GetLoadedResource(action.Amount.TokenIdentifier.Rri)
                ),
                { Type: InferredActionType.PayXrd or InferredActionType.BurnTokens, Action: Gateway.BurnTokens action } => new InferredAction(
                    inferredGatewayAction.Type,
                    fromAccount: _dbActionsPlanner.GetLoadedAccount(action.FromAccount.Address),
                    toAccount: null,
                    validator: null,
                    amount: TokenAmount.FromSubUnitsString(action.Amount.Value),
                    resource: _dbActionsPlanner.GetLoadedResource(action.Amount.TokenIdentifier.Rri)
                ),
                { Type: InferredActionType.StakeTokens, Action: Gateway.StakeTokens action } => new InferredAction(
                    inferredGatewayAction.Type,
                    fromAccount: _dbActionsPlanner.GetLoadedAccount(action.FromAccount.Address),
                    toAccount: null,
                    validator: _dbActionsPlanner.GetLoadedValidator(action.ToValidator.Address),
                    amount: TokenAmount.FromSubUnitsString(action.Amount.Value),
                    resource: _dbActionsPlanner.GetLoadedResource(action.Amount.TokenIdentifier.Rri)
                ),
                { Type: InferredActionType.UnstakeTokens, Action: Gateway.UnstakeTokens action } => new InferredAction(
                    inferredGatewayAction.Type,
                    fromAccount: null,
                    toAccount: _dbActionsPlanner.GetLoadedAccount(action.ToAccount.Address),
                    validator: _dbActionsPlanner.GetLoadedValidator(action.FromValidator.Address),
                    amount: TokenAmount.FromSubUnitsString(action.Amount.Value),
                    resource: _dbActionsPlanner.GetLoadedResource(action.Amount.TokenIdentifier.Rri)
                ),
                { Type: InferredActionType.SimpleTransfer or InferredActionType.SelfTransfer, Action: Gateway.TransferTokens action } => new InferredAction(
                    inferredGatewayAction.Type,
                    fromAccount: _dbActionsPlanner.GetLoadedAccount(action.FromAccount.Address),
                    toAccount: _dbActionsPlanner.GetLoadedAccount(action.ToAccount.Address),
                    validator: null,
                    amount: TokenAmount.FromSubUnitsString(action.Amount.Value),
                    resource: _dbActionsPlanner.GetLoadedResource(action.Amount.TokenIdentifier.Rri)
                ),
                _ => throw new ArgumentOutOfRangeException(),
            };
        }
        catch (ActionInferrer.InvalidTransactionException ex)
        {
            throw new InvalidTransactionException(transactionOpLocator, ex.Message);
        }
    }

    private void HandleAccountTransactions()
    {
        var accountAddresses = _referencedAccountAddressesInTransaction;
        var signedByPublicKey = _transaction!.Metadata.SignedBy?.Hex.ConvertFromHex();
        var signerAccountAddress = signedByPublicKey != null ? _entityDeterminer.CreateAccountAddress(signedByPublicKey) : null;

        if (signerAccountAddress != null)
        {
            accountAddresses.Add(signerAccountAddress);
        }

        _dbActionsPlanner.AddAccountTransactions(
            accountAddresses,
            () => _feePayer,
            signerAccountAddress,
            _transactionSummary!.StateVersion
        );
    }

    /// <summary>
    /// Handles Substates being booted up or shut down.
    /// </summary>
    /// <param name="createNewPartialSubstate">Creates a new partial substate if it were booted up. Does not need to set the operation group reference.</param>
    /// <param name="verifyDownedSubstateMatchesExisting">Verifies if an existing substate matches, to perform sanity checking when downing a substate.</param>
    /// <typeparam name="TSubstate">The substate type.</typeparam>
    private void HandleSubstateUpOrDown<TSubstate>(
        Func<TSubstate> createNewPartialSubstate,
        Func<TSubstate, bool> verifyDownedSubstateMatchesExisting
    )
        where TSubstate : SubstateBase
    {
        switch (_operation!.Substate.SubstateOperation)
        {
            case Substate.SubstateOperationEnum.BOOTUP:
                _dbActionsPlanner.UpSubstate(
                    GetCurrentTransactionOpLocator(),
                    _operation!.Substate.SubstateIdentifier.Identifier.ConvertFromHex(),
                    createNewPartialSubstate,
                    _dbOperationGroup!,
                    _operationIndexInGroup
                );
                return;
            case Substate.SubstateOperationEnum.SHUTDOWN:
                _dbActionsPlanner.DownSubstate(
                    GetCurrentTransactionOpLocator(),
                    _operation!.Substate.SubstateIdentifier.Identifier.ConvertFromHex(),
                    createNewPartialSubstate,
                    verifyDownedSubstateMatchesExisting,
                    _dbOperationGroup!,
                    _operationIndexInGroup
                );
                return;
            default:
                throw GenerateDetailedInvalidTransactionException(
                    $"Unknown substate operation type: {_operation!.Substate.SubstateOperation}"
                );
        }
    }

    private InvalidTransactionException GenerateDetailedInvalidTransactionException(string message)
    {
        return new InvalidTransactionException(GetCurrentTransactionOpLocator(), message);
    }

    private TransactionOpLocator GetCurrentTransactionOpLocator()
    {
        return new TransactionOpLocator(
            _transactionSummary!.StateVersion,
            _transaction!.TransactionIdentifier.Hash,
            _operationGroupIndex,
            _operationIndexInGroup
        );
    }
}
