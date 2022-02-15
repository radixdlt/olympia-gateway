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

using Common.Numerics;
using GatewayAPI.ApiSurface;
using Core = RadixCoreApi.Generated.Model;
using Gateway = RadixGatewayApi.Generated.Model;

namespace GatewayAPI.Services;

public static class TransactionBuilding
{
    public static readonly TokenAmount MinimumStake = TokenAmount.FromSubUnitsString("90000000000000000000");
    public static readonly int MaximumMessageLength = 255;
    public static readonly string OnlyValidGranularity = "1";

    public static Core.OperationGroup OperationGroupOf(params Core.Operation[] operations)
    {
        return new Core.OperationGroup(operations.ToList());
    }

    public static Core.Operation DebitOperation(this ValidatedAccountAddress fromAccount, ValidatedTokenAmount tokenAmount)
    {
        return ResourceOperation(fromAccount.ToEntityIdentifier(), tokenAmount.ToNegativeResourceAmount());
    }

    public static Core.Operation CreditOperation(this ValidatedAccountAddress toAccount, ValidatedTokenAmount tokenAmount)
    {
        return ResourceOperation(toAccount.ToEntityIdentifier(), tokenAmount.ToResourceAmount());
    }

    public static Core.Operation CreditPendingStakeVaultOperation(
        ValidatedAccountAddress toAccount,
        ValidatedValidatorAddress validatorAddress,
        ValidatedTokenAmount tokenAmount
    )
    {
        return ResourceOperation(toAccount.ToPreparedStakesEntityIdentifier(validatorAddress), tokenAmount.ToResourceAmount());
    }

    public static Core.Operation DebitStakeVaultOperation(
        ValidatedAccountAddress account,
        ValidatedValidatorAddress validatorAddress,
        TokenAmount stakeUnitAmount
    )
    {
        return ResourceOperation(account.ToEntityIdentifier(), (-stakeUnitAmount).AsStakeUnitAmount(validatorAddress));
    }

    public static Core.Operation CreditPendingUnStakeVaultOperation(
        ValidatedAccountAddress account,
        ValidatedValidatorAddress validatorAddress,
        TokenAmount stakeUnitAmount
    )
    {
        return ResourceOperation(account.ToPreparedUnstakesEntityIdentifier(), stakeUnitAmount.AsStakeUnitAmount(validatorAddress));
    }

    public static Core.Operation CreateTokenData(this ValidatedResourceAddress resourceAddress, Core.TokenData tokenData)
    {
        return UpDataOperation(resourceAddress.ToEntityIdentifier(), tokenData);
    }

    public static Core.Operation CreateTokenMetadata(this ValidatedResourceAddress resourceAddress, Core.TokenMetadata tokenMetadata)
    {
        return UpDataOperation(resourceAddress.ToEntityIdentifier(), tokenMetadata);
    }

    public static Core.Operation UpdateValidatorRegistration(this ValidatedValidatorAddress validatorAddress, Core.PreparedValidatorRegistered preparedValidatorRegistered)
    {
        return UpDataOperation(validatorAddress.ToEntityIdentifier(), preparedValidatorRegistered);
    }

    public static Core.EntityIdentifier ToEntityIdentifier(this ValidatedAccountAddress accountAddress)
    {
        return new Core.EntityIdentifier(
            address: accountAddress.Address,
            subEntity: null
        );
    }

    public static Core.EntityIdentifier ToEntityIdentifier(this ValidatedResourceAddress resourceAddress)
    {
        return new Core.EntityIdentifier(
            address: resourceAddress.Rri,
            subEntity: null
        );
    }

    public static Core.EntityIdentifier ToEntityIdentifier(this ValidatedValidatorAddress validatorAddress)
    {
        return new Core.EntityIdentifier(
            address: validatorAddress.Address,
            subEntity: null
        );
    }

    public static Core.EntityIdentifier ToPreparedStakesEntityIdentifier(
        this ValidatedAccountAddress accountAddress,
        ValidatedValidatorAddress validatedValidatorAddress
    )
    {
        return new Core.EntityIdentifier(
            address: accountAddress.Address,
            subEntity: new Core.SubEntity(
                "prepared_stakes",
                new Core.SubEntityMetadata(
                    validatorAddress: validatedValidatorAddress.Address
                )
            )
        );
    }

    public static Core.EntityIdentifier ToPreparedUnstakesEntityIdentifier(
        this ValidatedAccountAddress accountAddress
    )
    {
        return new Core.EntityIdentifier(
            address: accountAddress.Address,
            subEntity: new Core.SubEntity(
                "prepared_unstakes",
                metadata: null
            )
        );
    }

    public static Core.ResourceAmount AsStakeUnitAmount(
        this TokenAmount tokenAmount,
        ValidatedValidatorAddress validatorAddress
    )
    {
        return new Core.ResourceAmount(
            tokenAmount.ToSubUnitString(),
            new Core.StakeUnitResourceIdentifier(validatorAddress: validatorAddress.Address)
        );
    }

    public static Core.ResourceAmount ToResourceAmount(this ValidatedTokenAmount tokenAmount)
    {
        return new Core.ResourceAmount(
            tokenAmount.Amount.ToSubUnitString(),
            new Core.TokenResourceIdentifier(tokenAmount.Rri)
        );
    }

    public static Core.ResourceAmount ToNegativeResourceAmount(this ValidatedTokenAmount tokenAmount)
    {
        return new Core.ResourceAmount(
            (-tokenAmount.Amount).ToSubUnitString(),
            new Core.TokenResourceIdentifier(tokenAmount.Rri)
        );
    }

    private static Core.Operation ResourceOperation(
        Core.EntityIdentifier entityIdentifier,
        Core.ResourceAmount resourceAmount
    )
    {
        return new Core.Operation(
            "Resource",
            entityIdentifier,
            substate: null,
            amount: resourceAmount,
            data: null,
            metadata: null
        );
    }

    private static Core.Operation UpDataOperation(
        Core.EntityIdentifier entityIdentifier,
        Core.DataObject dataObject
    )
    {
        return new Core.Operation(
            "Data",
            entityIdentifier,
            substate: null,
            amount: null,
            data: new Core.Data(Core.Data.ActionEnum.CREATE, dataObject),
            metadata: null
        );
    }

    /// <summary>
    /// Note: This isn't supported in the Core API at present. Downs are typically handled automatically.
    /// </summary>
    private static Core.Operation DownDataOperation(
        Core.EntityIdentifier entityIdentifier,
        Core.DataObject dataObject
    )
    {
        return new Core.Operation(
            "Data",
            entityIdentifier,
            substate: null,
            amount: null,
            data: new Core.Data(Core.Data.ActionEnum.DELETE, dataObject),
            metadata: null
        );
    }
}
