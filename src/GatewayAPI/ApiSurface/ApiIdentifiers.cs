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

using Common.Database.Models.Ledger.Normalization;
using Common.Extensions;
using Common.Numerics;
using GatewayAPI.Exceptions;
using Core = RadixCoreApi.Generated.Model;
using Gateway = RadixGatewayApi.Generated.Model;

namespace GatewayAPI.ApiSurface;

public static class ApiIdentifiers
{
    public static Gateway.NetworkIdentifier AsNetworkIdentifier(this string networkName)
    {
        return new Gateway.NetworkIdentifier(networkName);
    }

    public static Gateway.TokenAmount AsGatewayTokenAmount(this ValidatedTokenAmount tokenAmount)
    {
        return new Gateway.TokenAmount(tokenAmount.Amount.ToSubUnitString(), tokenAmount.Rri.AsGatewayTokenIdentifier());
    }

    public static Gateway.TokenAmount AsGatewayTokenAmount(this TokenAmount tokenAmount, Gateway.TokenIdentifier tokenIdentifier)
    {
        return new Gateway.TokenAmount(tokenAmount.ToSubUnitString(), tokenIdentifier);
    }

    public static Gateway.TokenAmount AsGatewayTokenAmount(this TokenAmount tokenAmount, Resource resource)
    {
        return new Gateway.TokenAmount(tokenAmount.ToSubUnitString(), resource.ResourceIdentifier.AsGatewayTokenIdentifier());
    }

    public static string AsXrdString(this Gateway.TokenAmount apiTokenAmount)
    {
        return $"{TokenAmount.FromSubUnitsString(apiTokenAmount.Value)} XRD";
    }

    public static string AsStringWithUnits(this Gateway.TokenAmount apiTokenAmount)
    {
        return apiTokenAmount.TokenIdentifier.Rri.StartsWith("xrd_")
            ? AsXrdString(apiTokenAmount) // xrd is a reserved symbol, so we can avoid sharing the full RRI
            : $"{TokenAmount.FromSubUnitsString(apiTokenAmount.Value)} {apiTokenAmount.TokenIdentifier.Rri}";
    }

    public static Gateway.TokenAmount AsGatewayTokenAmount(this Core.ResourceAmount resourceAmount)
    {
        if (resourceAmount.ResourceIdentifier is not Core.TokenResourceIdentifier tokenResourceIdentifier)
        {
            throw new InvalidCoreApiResponseException(
                "Expected a response from the core API to have a tokenResourceIdentifier but it was another kind of resourceIdentifier"
            );
        }

        return new Gateway.TokenAmount(resourceAmount.Value, tokenResourceIdentifier.Rri.AsGatewayTokenIdentifier());
    }

    public static Gateway.TokenAmount AsGatewayTokenAmount(this TokenAmount tokenAmount, string rri)
    {
        return new Gateway.TokenAmount(tokenAmount.ToSubUnitString(), rri.AsGatewayTokenIdentifier());
    }

    public static Gateway.ValidatorIdentifier AsGatewayValidatorIdentifier(this Validator validator)
    {
        return new Gateway.ValidatorIdentifier(validator.Address);
    }

    public static Gateway.ValidatorIdentifier AsGatewayValidatorIdentifier(this string validatorAddress)
    {
        return new Gateway.ValidatorIdentifier(validatorAddress);
    }

    public static Gateway.TokenIdentifier AsGatewayTokenIdentifier(this Resource resource)
    {
        return new Gateway.TokenIdentifier(resource.ResourceIdentifier);
    }

    public static Gateway.TokenIdentifier AsGatewayTokenIdentifier(this string rri)
    {
        return new Gateway.TokenIdentifier(rri);
    }

    public static Gateway.AccountIdentifier AsGatewayAccountIdentifier(this Account account)
    {
        return new Gateway.AccountIdentifier(account.Address);
    }

    public static Gateway.AccountIdentifier AsGatewayAccountIdentifier(this string accountAddress)
    {
        return new Gateway.AccountIdentifier(accountAddress);
    }

    public static Gateway.AccountIdentifier? AsOptionalGatewayAccountIdentifier(this Account? account)
    {
        return account == null ? null : new Gateway.AccountIdentifier(account.Address);
    }

    public static Gateway.AccountIdentifier? AsOptionalGatewayAccountIdentifier(this string? accountAddress)
    {
        return accountAddress == null ? null : new Gateway.AccountIdentifier(accountAddress);
    }

    public static Gateway.TransactionIdentifier AsGatewayTransactionIdentifier(this string hexTransactionId)
    {
        return new Gateway.TransactionIdentifier(hexTransactionId);
    }

    public static Gateway.TransactionIdentifier AsGatewayTransactionIdentifier(this Core.TransactionIdentifier transactionIdentifier)
    {
        return new Gateway.TransactionIdentifier(transactionIdentifier.Hash);
    }

    public static Gateway.TransactionIdentifier AsGatewayTransactionIdentifier(this byte[] transactionIdentifierHash)
    {
        return new Gateway.TransactionIdentifier(transactionIdentifierHash.ToHex());
    }
}
