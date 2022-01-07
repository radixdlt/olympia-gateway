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

using Common.Addressing;
using Common.Extensions;
using GatewayAPI.ApiSurface;
using GatewayAPI.Database;
using GatewayAPI.Exceptions;
using System.Globalization;
using Core = RadixCoreApi.Generated.Model;
using Gateway = RadixGatewayApi.Generated.Model;
using TokenAmount = Common.Numerics.TokenAmount;

namespace GatewayAPI.Services;

public record MappedTransaction(
    List<Core.OperationGroup> OperationGroups,
    Dictionary<string, TokenAmount> BeforeBalances,
    Dictionary<string, TokenAmount> BalanceChanges
);

/// <summary>
/// A stateful class for building a transaction and checking it's valid against the current version of state.
/// </summary>
public class TransactionBuilder
{
    private readonly IValidations _validations;
    private readonly IAccountQuerier _accountQuerier;
    private readonly IValidatorQuerier _validatorQuerier;
    private readonly ITokenQuerier _tokenQuerier;
    private readonly INetworkConfigurationProvider _networkConfigurationProvider;
    private readonly Gateway.LedgerState _ledgerState;
    private readonly ValidatedAccountAddress _feePayer;

    // Pseudo-Variables
    private readonly HashSet<string> _createdFeePayerOwnedMutableResourceIdentifiers = new();
    private Dictionary<string, TokenAmount> _feePayerBeforeBalances = new();
    private Dictionary<string, TokenAmount> _feePayerCurrentBalances = new();
    private Dictionary<string, TokenAmount> _feePayerBalanceChanges = new();

    public TransactionBuilder(
        IValidations validations,
        IAccountQuerier accountQuerier,
        IValidatorQuerier validatorQuerier,
        ITokenQuerier tokenQuerier,
        INetworkConfigurationProvider networkConfigurationProvider,
        Gateway.LedgerState ledgerState,
        ValidatedAccountAddress feePayer
    )
    {
        _validations = validations;
        _accountQuerier = accountQuerier;
        _validatorQuerier = validatorQuerier;
        _tokenQuerier = tokenQuerier;
        _networkConfigurationProvider = networkConfigurationProvider;
        _ledgerState = ledgerState;
        _feePayer = feePayer;
    }

    /// <summary>
    /// Should only be called once per instance of TransactionBuilder.
    /// </summary>
    public async Task<MappedTransaction> MapAndValidateActions(List<Gateway.Action> requestActions)
    {
        await PrepareAccountBalancesForTracking();

        var operationGroups = new List<Core.OperationGroup>();
        foreach (var action in requestActions)
        {
            operationGroups.Add(await MapAction(action));
        }

        return new MappedTransaction(operationGroups, _feePayerBeforeBalances, _feePayerBalanceChanges);
    }

    private async Task PrepareAccountBalancesForTracking()
    {
        _feePayerBeforeBalances = await _accountQuerier.GetResourceBalancesByRri(_feePayer.Address, _ledgerState);
        _feePayerCurrentBalances = _feePayerBeforeBalances.ShallowClone();
        _feePayerBalanceChanges = new Dictionary<string, TokenAmount>();
    }

    private void ValidateAccountCredit(ValidatedAccountAddress account, ValidatedTokenAmount tokenAmount)
    {
        if (tokenAmount.Amount.IsNegative())
        {
            throw new ArgumentException("TokenAmount shouldn't be negative", nameof(tokenAmount));
        }

        if (account.Address != _feePayer.Address)
        {
            return;
        }

        _feePayerCurrentBalances.TrackBalanceDelta(tokenAmount.Rri, tokenAmount.Amount);
        _feePayerBalanceChanges.TrackBalanceDelta(tokenAmount.Rri, tokenAmount.Amount);
    }

    private record NotEnoughError(Gateway.TokenAmount RequestedAmount, Gateway.TokenAmount AvailableAmount);

    private void ValidateAccountDebit(
        Gateway.Action action,
        ValidatedAccountAddress account,
        ValidatedTokenAmount tokenAmount,
        Func<NotEnoughError, Exception> createNotEnoughException
    )
    {
        if (tokenAmount.Amount.IsNegative())
        {
            throw new ArgumentException("TokenAmount shouldn't be negative", nameof(tokenAmount));
        }

        if (account.Address != _feePayer.Address)
        {
            throw new InvalidActionException(action, "A fee payer cannot debit another account's balance");
        }

        var oldBalance = _feePayerCurrentBalances.GetValueOrDefault(tokenAmount.Rri);
        var newBalance = _feePayerCurrentBalances.TrackBalanceDelta(tokenAmount.Rri, -tokenAmount.Amount);
        _feePayerBalanceChanges.TrackBalanceDelta(tokenAmount.Rri, -tokenAmount.Amount);

        if (newBalance.IsNegative())
        {
            throw createNotEnoughException(new NotEnoughError(
                tokenAmount.Amount.AsGatewayTokenAmount(tokenAmount.Rri),
                oldBalance.AsGatewayTokenAmount(tokenAmount.Rri)
            ));
        }
    }

    private async Task<Core.OperationGroup> MapAction(Gateway.Action action)
    {
        return action switch
        {
            Gateway.TransferTokens transferTokens => MapTransferTokens(transferTokens),
            Gateway.BurnTokens burnTokens => await MapBurnTokens(burnTokens),
            Gateway.MintTokens mintTokens => await MapMintTokens(mintTokens),
            Gateway.StakeTokens stakeTokens => await MapStakeTokens(stakeTokens),
            Gateway.UnstakeTokens unstakeTokens => await MapUnstakeTokens(unstakeTokens),
            Gateway.CreateTokenDefinition createTokenDefinition => MapCreateTokenDefinition(createTokenDefinition),
            /* Users can supply a type which validates as an action (because it has a string type), but not as a type
               which matches the discriminator, so the deserializer doesn't deserialize it into one of the subtypes
               above. This error catches these issues */
            not null => throw new InvalidActionException(action, $"Action type of {action.Type} is not supported"),
            _ => throw new ArgumentOutOfRangeException(nameof(action), action, "Unhandled action type"),
        };
    }

    private Core.OperationGroup MapTransferTokens(Gateway.TransferTokens action)
    {
        var fromAccount = _validations.ExtractValidAccountAddress(action.FromAccount);
        var toAccount = _validations.ExtractValidAccountAddress(action.ToAccount);
        var tokenAmount = _validations.ExtractValidPositiveTokenAmount(action.Amount);

        ValidateAccountDebit(action, fromAccount, tokenAmount, error => new NotEnoughTokensForTransferException(error.RequestedAmount, error.AvailableAmount));
        ValidateAccountCredit(toAccount, tokenAmount);

        return TransactionBuilding.OperationGroupOf(
            fromAccount.DebitOperation(tokenAmount),
            toAccount.CreditOperation(tokenAmount)
        );
    }

    private async Task<Core.OperationGroup> MapBurnTokens(Gateway.BurnTokens action)
    {
        var fromAccount = _validations.ExtractValidAccountAddress(action.FromAccount);
        var tokenAmount = _validations.ExtractValidPositiveTokenAmount(action.Amount);

        if (!_createdFeePayerOwnedMutableResourceIdentifiers.Contains(tokenAmount.Rri))
        {
            var tokenData = await _tokenQuerier.GetTokenInfoAtState(tokenAmount.Rri, _ledgerState);

            if (!tokenData.TokenProperties.IsSupplyMutable)
            {
                throw new InvalidActionException(action, "Cannot burn non-mutable token");
            }

            if (tokenData.TokenProperties.Owner.Address != _feePayer.Address)
            {
                throw new InvalidActionException(action, "The fee payer burner isn't the token owner");
            }
        }

        if (fromAccount.Address != _feePayer.Address)
        {
            throw new InvalidActionException(action, "The fee payer can't burn from an account that's not their own");
        }

        ValidateAccountDebit(action, fromAccount, tokenAmount, error => new InvalidActionException(
            action,
            $"Cannot burn {error.RequestedAmount.AsStringWithUnits()} as the account only has {error.AvailableAmount.AsStringWithUnits()} remaining")
        );

        return TransactionBuilding.OperationGroupOf(
            fromAccount.DebitOperation(tokenAmount)
        );
    }

    private async Task<Core.OperationGroup> MapMintTokens(Gateway.MintTokens action)
    {
        var toAccount = _validations.ExtractValidAccountAddress(action.ToAccount);
        var tokenAmount = _validations.ExtractValidPositiveTokenAmount(action.Amount);

        if (!_createdFeePayerOwnedMutableResourceIdentifiers.Contains(tokenAmount.Rri))
        {
            var tokenData = await _tokenQuerier.GetTokenInfoAtState(tokenAmount.Rri, _ledgerState);

            if (!tokenData.TokenProperties.IsSupplyMutable)
            {
                throw new InvalidActionException(action, "Cannot mint non-mutable token");
            }

            if (tokenData.TokenProperties.Owner.Address != _feePayer.Address)
            {
                throw new InvalidActionException(action, "The fee payer minter isn't the token owner");
            }
        }

        ValidateAccountCredit(toAccount, tokenAmount);

        return TransactionBuilding.OperationGroupOf(
            toAccount.CreditOperation(tokenAmount)
        );
    }

    private async Task<Core.OperationGroup> MapStakeTokens(Gateway.StakeTokens action)
    {
        var account = _validations.ExtractValidAccountAddress(action.FromAccount);
        var validator = _validations.ExtractValidValidatorAddress(action.ToValidator);
        var tokenAmount = _validations.ExtractValidPositiveTokenAmount(action.Amount);

        if (tokenAmount.Amount < TransactionBuilding.MinimumStake)
        {
            throw new BelowMinimumStakeException(
                tokenAmount.AsGatewayTokenAmount(),
                TransactionBuilding.MinimumStake.AsGatewayTokenAmount(_networkConfigurationProvider.GetXrdTokenIdentifier())
            );
        }

        if (account.Address != _feePayer.Address)
        {
            throw new InvalidActionException(action, "The fee payer can't stake for an account that's not their own");
        }

        var validatorDetails = await _validatorQuerier.GetValidatorAtState(validator, _ledgerState);

        if (!validatorDetails.Properties.ExternalStakeAccepted &&
            validatorDetails.Properties.OwnerAccountIdentifier.Address != account.Address)
        {
            throw new CannotStakeException(
                owner: validatorDetails.Properties.OwnerAccountIdentifier.Address.AsGatewayAccountIdentifier(),
                user: account.Address.AsGatewayAccountIdentifier()
            );
        }

        ValidateAccountDebit(action, account, tokenAmount, error => new NotEnoughTokensForStakeException(error.RequestedAmount, error.AvailableAmount));

        return TransactionBuilding.OperationGroupOf(
            account.DebitOperation(tokenAmount),
            TransactionBuilding.CreditPendingStakeVaultOperation(account, validator, tokenAmount)
        );
    }

    private async Task<Core.OperationGroup> MapUnstakeTokens(Gateway.UnstakeTokens action)
    {
        var validator = _validations.ExtractValidValidatorAddress(action.FromValidator);
        var account = _validations.ExtractValidAccountAddress(action.ToAccount);

        if (account.Address != _feePayer.Address)
        {
            throw new InvalidActionException(action, "The fee payer can't unstake for an account that's not their own");
        }

        // We read in the stakeSnapshot at the given ledgerState so that the wallet can make the request against the given ledger state
        //  at which the stake estimate was given, to ensure the stakeUnits are calculated relative to that estimate
        var stakeSnapshot = await _accountQuerier.GetStakeSnapshotAtState(account, validator, _ledgerState);

        var stakeUnitsToUnstake = action switch
        {
            { Amount: { } xrdAmount, UnstakePercentage: 0 } => GetStakeUnitsToUnstakeGivenFixedXrdAmountRequested(validator, stakeSnapshot, xrdAmount),
            { Amount: null, UnstakePercentage: > 0 and var percentage } => GetStakeUnitsGivenUnstakePercentage(action, stakeSnapshot, percentage),
            _ => throw new InvalidActionException(action, "Only one of Amount or UnstakePercentage should be provided for an UnstakeTokens action"),
        };

        return TransactionBuilding.OperationGroupOf(
            TransactionBuilding.DebitStakeVaultOperation(account, validator, stakeUnitsToUnstake),
            TransactionBuilding.CreditPendingUnStakeVaultOperation(account, validator, stakeUnitsToUnstake)
        );
    }

    private TokenAmount GetStakeUnitsToUnstakeGivenFixedXrdAmountRequested(
        ValidatedValidatorAddress validator,
        AccountQuerier.CombinedStakeSnapshot stakeSnapshot,
        Gateway.TokenAmount xrdTokenAmount
    )
    {
        var requestedXrdToUnstake = _validations.ExtractValidPositiveXrdTokenAmount(xrdTokenAmount);

        var estimatedTotalXrdStaked = stakeSnapshot.ValidatorStakeSnapshot.EstimateXrdConversion(
            stakeSnapshot.AccountValidatorStakeSnapshot.TotalStakeUnits
        );

        if (requestedXrdToUnstake.Amount > estimatedTotalXrdStaked)
        {
            throw new NotEnoughTokensForUnstakeException(
                requestedXrdToUnstake.AsGatewayTokenAmount(),
                new Gateway.AccountStakeEntry(
                    validator.Address.AsGatewayValidatorIdentifier(),
                    estimatedTotalXrdStaked.AsGatewayTokenAmount(_networkConfigurationProvider.GetXrdTokenIdentifier())),
                new Gateway.AccountStakeEntry(
                    validator.Address.AsGatewayValidatorIdentifier(),
                    stakeSnapshot.AccountValidatorStakeSnapshot.TotalPreparedXrdStake.AsGatewayTokenAmount(_networkConfigurationProvider.GetXrdTokenIdentifier())
                )
            );
        }

        // If the amount to unstake is within 0.001 XRD, unstake everything to try to prevent the "dust" problem
        return (estimatedTotalXrdStaked - requestedXrdToUnstake.Amount) < TokenAmount.FromDecimalString("0.001")
            ? stakeSnapshot.AccountValidatorStakeSnapshot.TotalStakeUnits
            : (stakeSnapshot.AccountValidatorStakeSnapshot.TotalStakeUnits * requestedXrdToUnstake.Amount) / estimatedTotalXrdStaked;
    }

    private TokenAmount GetStakeUnitsGivenUnstakePercentage(Gateway.Action action, AccountQuerier.CombinedStakeSnapshot stakeSnapshot, decimal percentage)
    {
        if (percentage is not (> 0 and <= 100))
        {
            throw new InvalidActionException(action, "Percentage unstake must be > 0 and <= 100");
        }

        var proportionAsTokenAmount = TokenAmount.FromDecimalString((percentage / 100).ToString(CultureInfo.InvariantCulture));

        return (stakeSnapshot.AccountValidatorStakeSnapshot.TotalStakeUnits * proportionAsTokenAmount) / TokenAmount.OneFullUnit;
    }

    private Core.OperationGroup MapCreateTokenDefinition(Gateway.CreateTokenDefinition action)
    {
        var validatedSymbol = _validations.ExtractValidTokenSymbol(action.TokenProperties.Symbol).AsString;
        var ownerOrRecipient = action.ToAccount != null
            ? _validations.ExtractValidAccountAddress(action.ToAccount)
            : _feePayer;

        var resourceAddressStr = RadixBech32.GenerateResourceAddress(
            _feePayer.ByteAccountAddress.CompressedPublicKey,
            validatedSymbol,
            _networkConfigurationProvider.GetAddressHrps().ResourceHrpSuffix
        );

        var validatedGranularity = action.TokenProperties.Granularity;

        if (validatedGranularity != TransactionBuilding.OnlyValidGranularity)
        {
            throw new InvalidActionException(action, $"Only a granularity of {TransactionBuilding.OnlyValidGranularity} is currently supported");
        }

        var resourceAddress = _validations.ExtractValidResourceAddress(new Gateway.TokenIdentifier(resourceAddressStr));

        var tokenMetadata = new Core.TokenMetadata(
            symbol: validatedSymbol,
            /* The following properties aren't currently validated, beyond the cost of the bytes required to create them */
            name: action.TokenProperties.Name,
            description: action.TokenProperties.Description,
            url: action.TokenProperties.Url,
            iconUrl: action.TokenProperties.IconUrl
        );

        var validatedTokenSupply = _validations.ExtractValidPositiveTokenAmount(action.TokenSupply);

        if (validatedTokenSupply.Rri != resourceAddress.Rri)
        {
            throw new InvalidActionException(action, $"The token supply of the resource was against the rri {validatedTokenSupply.Rri} when it should have been {resourceAddress.Rri}");
        }

        return action.TokenProperties.IsSupplyMutable
            ? CreateMutableSupplyToken(action, resourceAddress, validatedTokenSupply, validatedGranularity, ownerOrRecipient, tokenMetadata)
            : CreateFixedSupplyToken(resourceAddress, validatedTokenSupply,  validatedGranularity, ownerOrRecipient, tokenMetadata);
    }

    private Core.OperationGroup CreateMutableSupplyToken(
        Gateway.CreateTokenDefinition action,
        ValidatedResourceAddress resourceAddress,
        ValidatedTokenAmount validatedTokenSupply,
        string validatedGranularity,
        ValidatedAccountAddress owner,
        Core.TokenMetadata tokenMetadata
    )
    {
        if (!validatedTokenSupply.Amount.IsZero())
        {
            throw new InvalidActionException(action, $"The token supply of a new mutable supply token should be 0 (as it can be minted in follow up actions), but you provided {validatedTokenSupply.Amount}");
        }

        if (owner.Address == _feePayer.Address)
        {
            _createdFeePayerOwnedMutableResourceIdentifiers.Add(resourceAddress.Rri);
        }

        /* On node, token data construction starts by calling Syscall.READDR_CLAIM syscall for the symbol
           and then DOWN'ing the REAddressClaim -- but this is done for us by the Core API on TokenData UP. */
        return TransactionBuilding.OperationGroupOf(
            resourceAddress.CreateTokenData(new Core.TokenData(
                granularity: validatedGranularity,
                isMutable: true,
                owner: owner.ToEntityIdentifier()
            )),
            resourceAddress.CreateTokenMetadata(tokenMetadata)
        );
    }

    private Core.OperationGroup CreateFixedSupplyToken(
        ValidatedResourceAddress resourceAddress,
        ValidatedTokenAmount validatedTokenSupply,
        string validatedGranularity,
        ValidatedAccountAddress recipient,
        Core.TokenMetadata tokenMetadata
    )
    {
        ValidateAccountCredit(recipient, validatedTokenSupply);

        /* On node, token data construction starts by calling Syscall.READDR_CLAIM syscall for the symbol
           and then DOWN'ing the REAddressClaim -- but this is done for us by the Core API on TokenData UP */
        return TransactionBuilding.OperationGroupOf(
            resourceAddress.CreateTokenData(new Core.TokenData(
                granularity: validatedGranularity,
                isMutable: false,
                owner: null
            )),
            /* For a fixed token supply, immediately pass the created supply to the recipient */
            recipient.CreditOperation(validatedTokenSupply),
            resourceAddress.CreateTokenMetadata(tokenMetadata)
        );
    }
}
