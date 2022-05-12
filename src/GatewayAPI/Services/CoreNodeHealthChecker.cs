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

using Common.Extensions;
using GatewayAPI.Configuration;
using GatewayAPI.Configuration.Models;
using GatewayAPI.CoreCommunications;
using GatewayAPI.Database;
using GatewayAPI.Exceptions;
using CoreApiModel = RadixCoreApi.Generated.Model;

namespace GatewayAPI.Services;

public interface ICoreNodeHealthChecker
{
    Task<CoreNodeHealthResult> CheckCoreNodeHealth(CancellationToken cancellationToken);
}

public record CoreNodeHealthResult(ILookup<CoreNodeStatus, CoreApiNode> CoreApiNodesByStatus);

// Using explicit integers for enum values
// because they're used for ordering the nodes (from best to worst).
public enum CoreNodeStatus
{
    HealthyAndSynced = 0,
    HealthyButLagging = 1,
    Unhealthy = 2,
}

/// <summary>
/// This contains references to a HttpClient (which should be temporary, due to caching stuff)
/// and a LedgerStateQuerier (which is a scoped service, as it contains a DataContext) - this service should thus be
/// scoped to a unit of work.
/// </summary>
public class CoreNodeHealthChecker : ICoreNodeHealthChecker
{
    private readonly ILogger _logger;
    private readonly HttpClient _httpClient;
    private readonly ILedgerStateQuerier _ledgerStateQuerier;
    private readonly IGatewayApiConfiguration _configuration;

    public CoreNodeHealthChecker(
        ILogger<CoreNodesSelectorService> logger,
        HttpClient httpClient,
        ILedgerStateQuerier ledgerStateQuerier,
        IGatewayApiConfiguration configuration)
    {
        _logger = logger;
        _httpClient = httpClient;
        _ledgerStateQuerier = ledgerStateQuerier;
        _configuration = configuration;
    }

    public async Task<CoreNodeHealthResult> CheckCoreNodeHealth(CancellationToken cancellationToken)
    {
        var enabledCoreNodeStateVersionLookupTasks = _configuration.GetCoreNodes()
            .Where(n => n.IsEnabled && !string.IsNullOrWhiteSpace(n.CoreApiAddress))
            .Select(n => GetCoreNodeStateVersion(n, cancellationToken));

        var ledgerStateVersionTask = _ledgerStateQuerier.GetLedgerStatus();

        var nodesStateVersions = (await Task.WhenAll(enabledCoreNodeStateVersionLookupTasks))
            .ToDictionary(p => p.CoreApiNode, p => p.StateVersion);

        var topOfLedgerStateVersion = (await ledgerStateVersionTask).TopOfLedgerStateVersion;

        var coreNodesByStatus = nodesStateVersions
            .Select(kv => (CoreApiNode: kv.Key, Status: DetermineNodeStatus(kv.Value, topOfLedgerStateVersion)))
            .ToLookup(p => p.Status, p => p.CoreApiNode);

        _logger.LogInformation(
            "Checking core nodes health, top of ledger state version is {}, core nodes by status = {}",
            topOfLedgerStateVersion, coreNodesByStatus);

        return new CoreNodeHealthResult(coreNodesByStatus);
    }

    private CoreNodeStatus DetermineNodeStatus(long? maybeNodeStateVersion, long topOfLedgerStateVersion)
    {
        _logger.LogInformation("Determine node status, node state version = {}, top of ledger = {}", maybeNodeStateVersion, topOfLedgerStateVersion);
        if (maybeNodeStateVersion == null)
        {
            return CoreNodeStatus.Unhealthy;
        }

        var syncedThreshold =
            topOfLedgerStateVersion - _configuration.GetCoreApiNodeHealth().MaxAllowedStateVersionLagToBeConsideredSynced;

        return maybeNodeStateVersion >= syncedThreshold
            ? CoreNodeStatus.HealthyAndSynced
            : CoreNodeStatus.HealthyButLagging;
    }

    private async Task<(CoreApiNode CoreApiNode, long? StateVersion)> GetCoreNodeStateVersion(
        CoreApiNode coreApiNode,
        CancellationToken cancellationToken)
    {
        var coreApiProvider = new CoreApiProvider(coreApiNode, _httpClient);
        try
        {
            var networkStatusResponse =
                await coreApiProvider.NetworkApi.NetworkStatusPostAsync(
                    new CoreApiModel.NetworkStatusRequest(new CoreApiModel.NetworkIdentifier(_configuration.GetNetworkName())),
                    cancellationToken
                );
            return (coreApiNode, networkStatusResponse.CurrentStateIdentifier.StateVersion);
        }
        catch (Exception ex)
        {
            if (ex.ShouldBeConsideredAppFatal())
            {
                _logger.LogError(ex, "An app-fatal error occurred. Rethrowing...");
                throw;
            }

            // If, for any reason, the node can't be reached then it's considered Unhealthy
            return (coreApiNode, null);
        }
    }
}
