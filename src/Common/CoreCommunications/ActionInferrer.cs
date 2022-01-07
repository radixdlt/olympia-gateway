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
using Common.Database.Models.Ledger.History;
using Common.Extensions;
using Common.Numerics;
using Core = RadixCoreApi.Generated.Model;
using Gateway = RadixGatewayApi.Generated.Model;

namespace Common.CoreCommunications;

public interface IActionInferrer
{
    OperationGroupSummarisation SummariseOperationGroup(Core.OperationGroup operationGroup);

    GatewayInferredAction? InferAction(
        bool isSystemTransaction,
        OperationGroupSummarisation summarisation,
        Func<string, ValidatorStakeSnapshot> stakeSnapshotsByValidatorAddress
    );
}

public record GatewayInferredAction(InferredActionType Type, Gateway.Action? Action);

public record EntityResource(Entity Entity, Core.ResourceIdentifier ResourceIdentifier);
public record AccountingEntry(Entity Entity, Core.ResourceIdentifier ResourceIdentifier, TokenAmount Delta);

public record OperationGroupSummarisation(
    Dictionary<Entity, Core.TokenData> TokenData,
    Dictionary<Entity, Core.TokenMetadata> TokenMetadata,
    Dictionary<EntityResource, TokenAmount> TrackedTotalChanges,
    HashSet<string> PendingStakeValidatorAddressesSeen
);

public class ActionInferrer : IActionInferrer
{
    private readonly IEntityDeterminer _entityDeterminer;

    public class InvalidTransactionException : Exception
    {
        public InvalidTransactionException(string message)
            : base(message)
        {
        }
    }

    public ActionInferrer(IEntityDeterminer entityDeterminer)
    {
        _entityDeterminer = entityDeterminer;
    }

    public OperationGroupSummarisation SummariseOperationGroup(Core.OperationGroup operationGroup)
    {
        var tokenDataByEntity = new Dictionary<Entity, Core.TokenData>();
        var tokenMetadataByEntity = new Dictionary<Entity, Core.TokenMetadata>();
        var trackedTotalChanges = new Dictionary<EntityResource, TokenAmount>();
        var pendingStakeValidatorAddressesSeen = new HashSet<string>();

        foreach (var operation in operationGroup.Operations)
        {
            var entity = _entityDeterminer.DetermineEntity(operation.EntityIdentifier);

            if (entity == null)
            {
                throw new InvalidTransactionException("Entity couldn't be parsed");
            }

            if (operation.IsCreateOf<Core.TokenData>(out var tokenData))
            {
                tokenDataByEntity.Add(entity, tokenData);
            }

            if (operation.IsCreateOf<Core.TokenMetadata>(out var tokenMetadata))
            {
                tokenMetadataByEntity.Add(entity, tokenMetadata);
            }

            // ReSharper disable once InvertIf - makes more sense like this is we wish to add more things to track in future
            if (operation.Amount != null)
            {
                var amount = TokenAmount.FromSubUnitsString(operation.Amount.Value);
                if (amount.IsNaN())
                {
                    throw new InvalidTransactionException($"Unparsable token amount value: {operation.Amount}");
                }

                trackedTotalChanges.TrackBalanceDelta(new EntityResource(entity, operation.Amount.ResourceIdentifier), amount);

                if (
                    operation.Amount.ResourceIdentifier is Core.StakeUnitResourceIdentifier stakeUnitResourceIdentifier
                    && entity.EntityType == EntityType.Account_PreparedUnstake
                )
                {
                    pendingStakeValidatorAddressesSeen.Add(stakeUnitResourceIdentifier.ValidatorAddress);
                }
            }
        }

        return new OperationGroupSummarisation(
            tokenDataByEntity,
            tokenMetadataByEntity,
            trackedTotalChanges,
            pendingStakeValidatorAddressesSeen
        );
    }

    public GatewayInferredAction? InferAction(
        bool isSystemTransaction,
        OperationGroupSummarisation summarisation,
        Func<string, ValidatorStakeSnapshot> stakeSnapshotsByValidatorAddress
    )
    {
        var (tokenData, tokenMetadata, trackedTotalChanges, _) = summarisation;

        var withdrawals = trackedTotalChanges
            .Where(t => t.Value.IsNegative())
            .Select(t => new AccountingEntry(t.Key.Entity, t.Key.ResourceIdentifier, t.Value))
            .ToList();

        var deposits = trackedTotalChanges
            .Where(t => t.Value.IsPositive())
            .Select(t => new AccountingEntry(t.Key.Entity, t.Key.ResourceIdentifier, t.Value))
            .ToList();

        if (tokenData.Any())
        {
            return InferTokenCreationAction(tokenData, tokenMetadata, withdrawals, deposits);
        }

        if (withdrawals.Count == 0 && deposits.Count == 0)
        {
            return null;
        }

        if (withdrawals.Count > 1)
        {
            if (isSystemTransaction)
            {
                return new GatewayInferredAction(InferredActionType.Complex, null);
            }

            throw new InvalidTransactionException("Invalid operation group in non-system transaction with multiple vault withdrawals");
        }

        if (deposits.Count > 1)
        {
            return new GatewayInferredAction(InferredActionType.Complex, null);
        }

        if (deposits.Count == 1 && withdrawals.Count == 0)
        {
            var mint = deposits.First();
            if (mint.ResourceIdentifier is not Core.TokenResourceIdentifier tokenResourceIdentifier)
            {
                return null;
            }

            var rri = tokenResourceIdentifier.Rri;

            var entity = mint.Entity;
            if (entity.EntityType != EntityType.Account)
            {
                throw new InvalidTransactionException("Token minted to non-account");
            }

            return new GatewayInferredAction(
                _entityDeterminer.IsXrd(rri) ? InferredActionType.MintXrd : InferredActionType.MintTokens,
                new Gateway.MintTokens(
                    toAccount: AccountFrom(entity),
                    amount: TokenAmountFrom(mint.Delta, rri)
                )
            );
        }

        if (withdrawals.Count == 1 && deposits.Count == 0)
        {
            var burn = withdrawals.First();
            if (burn.ResourceIdentifier is not Core.TokenResourceIdentifier tokenResourceIdentifier)
            {
                return null;
            }

            var rri = tokenResourceIdentifier.Rri;

            var entity = burn.Entity;
            if (entity.EntityType != EntityType.Account)
            {
                throw new InvalidTransactionException("Token burned from non-account");
            }

            return new GatewayInferredAction(
                _entityDeterminer.IsXrd(rri) ? InferredActionType.PayXrd : InferredActionType.BurnTokens,
                new Gateway.BurnTokens(
                    fromAccount: AccountFrom(entity),
                    amount: TokenAmountFrom(-burn.Delta, rri)
                )
            );
        }

        // Exactly one sender and receiver
        var sender = withdrawals.First().Entity;
        var recipient = deposits.First().Entity;
        var sentResource = withdrawals.First().ResourceIdentifier;
        var receivedResource = deposits.First().ResourceIdentifier;
        var sentAmount = -withdrawals.First().Delta;
        var receivedAmount = deposits.First().Delta;

        if (recipient.EntityType == EntityType.Account_PreparedStake)
        {
            if (sender.EntityType != EntityType.Account)
            {
                throw new InvalidTransactionException("Prepared stake from non-account");
            }

            if (sentResource is not Core.TokenResourceIdentifier tokenResourceIdentifier || !_entityDeterminer.IsXrd(tokenResourceIdentifier.Rri))
            {
                throw new InvalidTransactionException("Prepared stake using non-xrd resource");
            }

            return new GatewayInferredAction(
                InferredActionType.StakeTokens,
                new Gateway.StakeTokens(
                    fromAccount: AccountFrom(sender),
                    toValidator: ValidatorFrom(recipient),
                    amount: TokenAmountFrom(sentAmount, _entityDeterminer.GetXrdAddress())
                )
            );
        }

        if (recipient.EntityType == EntityType.Account_PreparedUnstake)
        {
            if (sender.EntityType != EntityType.Account)
            {
                throw new InvalidTransactionException("Prepared stake from non-account");
            }

            if (!sentResource.Equals(receivedResource))
            {
                throw new InvalidTransactionException("Prepared unstake send and receive resources aren't equal");
            }

            if (sentAmount != receivedAmount)
            {
                throw new InvalidTransactionException("Prepared unstake send and receive amounts weren't equal StakeUnits");
            }

            if (sentResource is not Core.StakeUnitResourceIdentifier stakeUnitResourceIdentifier)
            {
                throw new InvalidTransactionException("Prepared unstake using non-stake unit resource");
            }

            var xrdEstimate = stakeSnapshotsByValidatorAddress(stakeUnitResourceIdentifier.ValidatorAddress).EstimateXrdConversion(sentAmount);

            return new GatewayInferredAction(
                InferredActionType.UnstakeTokens,
                new Gateway.UnstakeTokens(
                    fromValidator: new Gateway.ValidatorIdentifier(stakeUnitResourceIdentifier.ValidatorAddress),
                    toAccount: AccountFrom(sender),
                    amount: TokenAmountFrom(xrdEstimate, _entityDeterminer.GetXrdAddress()),
                    unstakePercentage: default
                )
            );
        }

        if (sender.EntityType == EntityType.Account && recipient.EntityType == EntityType.Account)
        {
            if (sentAmount != receivedAmount)
            {
                throw new InvalidTransactionException("Transfer send and receive amounts weren't equal");
            }

            if (sentResource is not Core.TokenResourceIdentifier tokenResourceIdentifier)
            {
                throw new InvalidTransactionException("Cannot transfer non-token");
            }

            return new GatewayInferredAction(
                InferredActionType.SimpleTransfer,
                new Gateway.TransferTokens(
                    fromAccount: AccountFrom(sender),
                    toAccount: AccountFrom(recipient),
                    amount: TokenAmountFrom(sentAmount, tokenResourceIdentifier.Rri)
                )
            );
        }

        return null;
    }

    // ReSharper disable once ParameterOnlyUsedForPreconditionCheck.Local
    private GatewayInferredAction InferTokenCreationAction(
        Dictionary<Entity, Core.TokenData> tokenDataDict,
        Dictionary<Entity, Core.TokenMetadata> tokenMetaDataDict,
        List<AccountingEntry> withdrawals,
        List<AccountingEntry> deposits
    )
    {
        if (withdrawals.Count > 0)
        {
            throw new InvalidTransactionException("Should be no withdrawals in Token Creation");
        }

        if (deposits.Count > 1)
        {
            throw new InvalidTransactionException("Should be no more than 1 account credited with tokens during Token Creation");
        }

        if (tokenDataDict.Count != 1)
        {
            throw new InvalidTransactionException("There should be exactly one token data created in a given operation group");
        }

        if (tokenMetaDataDict.Count != 1)
        {
            throw new InvalidTransactionException("There should be exactly one token metadata created in a given operation group");
        }

        var toAccountEntity = deposits.FirstOrDefault()?.Entity;
        var tokenDataEntity = tokenDataDict.First().Key;
        var tokenData = tokenDataDict.First().Value;
        var tokenMetadataEntity = tokenMetaDataDict.First().Key;
        var tokenMetadata = tokenMetaDataDict.First().Value;

        if (toAccountEntity != null && toAccountEntity.EntityType != EntityType.Account)
        {
            throw new InvalidTransactionException("Token creation credited to non-account");
        }

        if (tokenDataEntity != tokenMetadataEntity || tokenDataEntity.EntityType != EntityType.Resource)
        {
            throw new InvalidTransactionException("Token Data Entity and MetaData Entity weren't the same");
        }

        var rri = tokenDataEntity.ResourceAddress!;
        var amount = deposits.FirstOrDefault()?.Delta ?? TokenAmount.Zero;

        var tokenProperties = new Gateway.TokenProperties(
            name: tokenMetadata.Name,
            description: tokenMetadata.Description,
            iconUrl: tokenMetadata.IconUrl,
            url: tokenMetadata.Url,
            symbol: tokenMetadata.Symbol,
            isSupplyMutable: tokenData.IsMutable,
            granularity: tokenData.Granularity,
            owner: OptionalAccountFrom(_entityDeterminer.DetermineEntity(tokenData.Owner))
        );

        return new GatewayInferredAction(
            InferredActionType.CreateTokenDefinition,
            new Gateway.CreateTokenDefinition(
                tokenProperties,
                TokenAmountFrom(amount, rri),
                OptionalAccountFrom(toAccountEntity)
            )
        );
    }

    private Gateway.TokenAmount TokenAmountFrom(TokenAmount tokenAmount, string rri)
    {
        return new Gateway.TokenAmount(tokenAmount.ToSubUnitString(), new Gateway.TokenIdentifier(rri));
    }

    private Gateway.AccountIdentifier? OptionalAccountFrom(Entity? entity)
    {
        return entity == null ? null : new Gateway.AccountIdentifier(entity.AccountAddress!);
    }

    private Gateway.AccountIdentifier AccountFrom(Entity entity)
    {
        return new Gateway.AccountIdentifier(entity.AccountAddress!);
    }

    private Gateway.ValidatorIdentifier ValidatorFrom(Entity entity)
    {
        return new Gateway.ValidatorIdentifier(entity.ValidatorAddress!);
    }
}
