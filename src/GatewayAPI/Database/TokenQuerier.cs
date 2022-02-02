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

using Common.Database;
using Common.Database.Models.Ledger;
using Common.Database.Models.Ledger.History;
using Common.Database.Models.Ledger.Normalization;
using Common.Database.Models.Ledger.Substates;
using Common.Numerics;
using GatewayAPI.ApiSurface;
using GatewayAPI.Exceptions;
using Microsoft.EntityFrameworkCore;
using Gateway = RadixGatewayApi.Generated.Model;

namespace GatewayAPI.Database;

public interface ITokenQuerier
{
    Task<Gateway.Token> GetTokenInfoAtState(string tokenRri, Gateway.LedgerState ledgerState);

    Task<CreatedTokenData> GetCreatedTokenProperties(string tokenRri, LedgerOperationGroup operationGroup);
}

public record CreatedTokenData(Gateway.TokenProperties TokenProperties, Gateway.TokenAmount TokenSupply);

public class TokenQuerier : ITokenQuerier
{
    private readonly GatewayReadOnlyDbContext _dbContext;

    public TokenQuerier(GatewayReadOnlyDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<Gateway.Token> GetTokenInfoAtState(string tokenRri, Gateway.LedgerState ledgerState)
    {
        var resource = await _dbContext.Resource(tokenRri, ledgerState._Version).SingleOrDefaultAsync();

        if (resource == null)
        {
            throw new TokenNotFoundException(tokenRri);
        }

        var tokenIdentifier = tokenRri.AsGatewayTokenIdentifier();
        var tokenSupply = await GetTokenSupplyAtState(resource, ledgerState);
        return new Gateway.Token(
            tokenIdentifier,
            tokenSupply.ResourceSupply.TotalSupply.AsGatewayTokenAmount(tokenIdentifier),
            new Gateway.TokenInfo(
                tokenSupply.ResourceSupply.TotalMinted.AsGatewayTokenAmount(tokenIdentifier),
                tokenSupply.ResourceSupply.TotalBurnt.AsGatewayTokenAmount(tokenIdentifier)
            ),
            await GetTokenPropertiesAtState(resource, ledgerState)
        );
    }

    public async Task<CreatedTokenData> GetCreatedTokenProperties(string tokenRri, LedgerOperationGroup operationGroup)
    {
        var tokenDataSubstates = await _dbContext.ResourceDataSubstates
            .Where(s =>
                s.UpStateVersion == operationGroup.ResultantStateVersion
                && s.UpOperationGroupIndex == operationGroup.OperationGroupIndex
            )
            .Include(s => s.TokenData!.Owner)
            .ToListAsync();

        var tokenData = tokenDataSubstates.Find(s => s.Type == ResourceDataSubstateType.TokenData)?.TokenData;
        var tokenMetadata = tokenDataSubstates.Find(s => s.Type == ResourceDataSubstateType.TokenMetadata)?.TokenMetadata;

        if (tokenDataSubstates.Count > 2)
        {
            throw new InvalidStateException(
                $"More than one TokenData or TokenMetaData at (stateVersion, opGroupIndex) of ({operationGroup.ResultantStateVersion}, {operationGroup.OperationGroupIndex})"
            );
        }

        var tokenProperties = CreateTokenProperties(tokenRri, tokenData, tokenMetadata, operationGroup.ResultantStateVersion);

        var tokenSupplyAmount = tokenProperties.IsSupplyMutable
            ? TokenAmount.Zero.AsGatewayTokenAmount(tokenRri)
            : (await GetFixedTokenMintInOperationGroup(tokenRri, operationGroup)).AsGatewayTokenAmount(tokenRri);

        return new CreatedTokenData(tokenProperties, tokenSupplyAmount);
    }

    private async Task<TokenAmount> GetFixedTokenMintInOperationGroup(string tokenRri, LedgerOperationGroup operationGroup)
    {
        var substates = await _dbContext.AccountResourceBalanceSubstates
            .Where(s =>
                s.UpStateVersion == operationGroup.ResultantStateVersion
                && s.UpOperationGroupIndex == operationGroup.OperationGroupIndex
            )
            .Include(s => s.Resource)
            .ToListAsync();

        if (substates.Count != 1)
        {
            throw new InvalidStateException(
                $"Expected to see 1 token mint for fixed token supply creation of {tokenRri} but saw {substates.Count} at (stateVersion, opGroupIndex) of ({operationGroup.ResultantStateVersion}, {operationGroup.OperationGroupIndex})"
            );
        }

        var substate = substates.First();
        if (substate.Resource.ResourceIdentifier != tokenRri)
        {
            throw new InvalidStateException(
                $"Found 1 upped resource for fixed token supply creation of {tokenRri} but it was against the wrong rri {tokenRri} at (stateVersion, opGroupIndex) of ({operationGroup.ResultantStateVersion}, {operationGroup.OperationGroupIndex})"
            );
        }

        return substate.Amount;
    }

    private async Task<ResourceSupplyHistory> GetTokenSupplyAtState(Resource resource, Gateway.LedgerState ledgerState)
    {
        var resourceSupply = await _dbContext.ResourceSupplyHistoryAtVersionForResourceId(ledgerState._Version, resource.Id)
            .SingleOrDefaultAsync();

        if (resourceSupply == null)
        {
            throw new TokenNotFoundException(resource.ResourceIdentifier);
        }

        return resourceSupply;
    }

    private async Task<Gateway.TokenProperties> GetTokenPropertiesAtState(Resource resource, Gateway.LedgerState ledgerState)
    {
        var stateVersion = ledgerState._Version;

        var tokenDataSubstates = await _dbContext.ResourceDataSubstates.UpAtVersion(stateVersion)
            .Where(ds => ds.ResourceId == resource.Id)
            .OrderByDescending(ds => ds.UpStateVersion)
            .Include(s => s.TokenData!.Owner)
            .ToListAsync();

        var tokenData = tokenDataSubstates.Find(s => s.Type == ResourceDataSubstateType.TokenData)?.TokenData;
        var tokenMetadata = tokenDataSubstates.Find(s => s.Type == ResourceDataSubstateType.TokenMetadata)?.TokenMetadata;

        if (tokenDataSubstates.Count > 2)
        {
            throw new InvalidStateException(
                $"More than one TokenData or TokenMetaData matched for rri '{resource.ResourceIdentifier}' at stateVersion {stateVersion}");
        }

        return CreateTokenProperties(resource.ResourceIdentifier, tokenData, tokenMetadata, stateVersion);
    }

    private Gateway.TokenProperties CreateTokenProperties(
        string tokenRri,
        TokenData? tokenData,
        TokenMetadata? tokenMetadata,
        long stateVersion
    )
    {
        if (tokenData == null && tokenMetadata == null)
        {
            throw new TokenNotFoundException(tokenRri);
        }

        if (tokenData == null)
        {
            throw new InvalidStateException(
                $"TokenData was missing but TokenMetadata wasn't missing for rri '{tokenRri}' at stateVersion {stateVersion}");
        }

        if (tokenMetadata == null)
        {
            throw new InvalidStateException(
                $"TokenMetaData was missing but TokenData wasn't missing for rri '{tokenRri}' at stateVersion {stateVersion}");
        }

        return new Gateway.TokenProperties(
            name: tokenMetadata.Name,
            description: tokenMetadata.Description,
            iconUrl: tokenMetadata.IconUrl,
            url: tokenMetadata.Url,
            symbol: tokenMetadata.Symbol,
            isSupplyMutable: tokenData.IsMutable,
            granularity: tokenData.Granularity.ToSubUnitString(),
            owner: tokenData.Owner.AsOptionalGatewayAccountIdentifier()
        );
    }
}
