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
using DataAggregator.Configuration.Models;
using DataAggregator.DependencyInjection;
using DataAggregator.NodeScopedServices;

namespace DataAggregator.GlobalServices;

public interface INodeWorkersRunnerRegistry
{
    Task EnsureCorrectNodeServicesRunning(List<NodeAppSettings> nodes, CancellationToken cancellationToken);

    Task StopAllWorkers(CancellationToken cancellationToken = default);
}

public class NodeWorkersRunnerRegistry : INodeWorkersRunnerRegistry
{
    private const int ErrorStartupBlockTimeSeconds = 20;

    private readonly ILogger<INodeWorkersRunnerRegistry> _logger;
    private readonly INodeWorkersRunnerFactory _nodeWorkersRunnerFactory;
    private readonly Dictionary<NodeAppSettings, NodeWorkersRunner> _servicesMap = new();
    private readonly Dictionary<string, Task> _startupBlocklist = new();
    private readonly object _servicesMapLock = new();

    public NodeWorkersRunnerRegistry(ILogger<NodeWorkersRunnerRegistry> logger, INodeWorkersRunnerFactory nodeWorkersRunnerFactory)
    {
        _logger = logger;
        _nodeWorkersRunnerFactory = nodeWorkersRunnerFactory;
    }

    public async Task EnsureCorrectNodeServicesRunning(List<NodeAppSettings> enabledNodes, CancellationToken cancellationToken)
    {
        var startTask = StartNodeWorkersForNodes(GetWorkersToStart(enabledNodes), cancellationToken);
        var endTask = StopNodeWorkersForNodes(GetWorkersToStop(enabledNodes), cancellationToken);

        await Task.WhenAll(startTask, endTask);
    }

    public async Task StopAllWorkers(CancellationToken cancellationToken)
    {
        await StopNodeWorkersForNodes(GetAllWorkers(), cancellationToken);
    }

    private List<NodeAppSettings> GetWorkersToStart(List<NodeAppSettings> enabledNodesSettings)
    {
        lock (_servicesMapLock)
        {
            return enabledNodesSettings
                .Where(n => !_servicesMap.ContainsKey(n))
                .Where(n => !_startupBlocklist.ContainsKey(n.Name) || _startupBlocklist[n.Name].IsCompleted)
                .ToList();
        }
    }

    private List<NodeAppSettings> GetWorkersToStop(List<NodeAppSettings> enabledNodesSettings)
    {
        lock (_servicesMapLock)
        {
            return _servicesMap
                .SelectNonNull(kvp =>
                {
                    var (nodeAppSettings, nodeWorkersRunner) = kvp;

                    // If the workers get stopped for some reason, then we should stop them and clear them from the
                    // service map so they can be restarted.
                    var workersAreStopped = nodeWorkersRunner.Status == NodeWorkersRunnerStatus.Stopped;
                    var workersAreUnhealthy = !nodeWorkersRunner.IsHealthy();
                    var nodeIsNoLongerEnabledWithTheseSettings = !enabledNodesSettings.Contains(nodeAppSettings);

                    return (workersAreStopped || workersAreUnhealthy || nodeIsNoLongerEnabledWithTheseSettings) ? nodeAppSettings : null;
                })
                .ToList();
        }
    }

    private List<NodeAppSettings> GetAllWorkers()
    {
        lock (_servicesMapLock)
        {
            return _servicesMap.Keys.ToList();
        }
    }

    private Task StartNodeWorkersForNodes(IEnumerable<NodeAppSettings> nodes, CancellationToken cancellationToken)
    {
        return Task.WhenAll(nodes.Select(n => CreateAndStartNodeWorkersIfNotExists(n, cancellationToken)));
    }

    private async Task CreateAndStartNodeWorkersIfNotExists(NodeAppSettings node, CancellationToken cancellationToken)
    {
        NodeWorkersRunner nodeWorkersRunner;
        lock (_servicesMapLock)
        {
            if (_servicesMap.ContainsKey(node))
            {
                return;
            }

            nodeWorkersRunner = _nodeWorkersRunnerFactory.CreateWorkersForNode(node);
            _servicesMap.Add(node, nodeWorkersRunner);
        }

        try
        {
            _logger.LogInformation("Initializing for node: {NodeName}", node.Name);
            await nodeWorkersRunner.Initialize(cancellationToken);
            _logger.LogInformation("Starting workers for node: {NodeName}", node.Name);
            await nodeWorkersRunner.StartWorkers(cancellationToken);
            _logger.LogInformation("Workers for node started successfully: {NodeName}", node.Name);
        }
        catch (Exception ex)
        {
            if (ex.ShouldBeConsideredAppFatal())
            {
                _logger.LogError(ex, "Unexpected app-fatal error initializing or starting up services for node: {NodeName}. Re-throwing", node.Name);
                throw;
            }

            _logger.LogError(
                ex,
                "Error initializing or starting up services for node: {NodeName}. We won't try again for {ErrorStartupBlockTimeSeconds} seconds. Now clearing up...",
                node.Name,
                ErrorStartupBlockTimeSeconds
            );

            lock (_servicesMapLock)
            {
                _startupBlocklist[node.Name] = Task.Delay(TimeSpan.FromSeconds(ErrorStartupBlockTimeSeconds), cancellationToken);
            }

            await StopNodeWorkers(node, cancellationToken);
        }
    }

    private Task StopNodeWorkersForNodes(IEnumerable<NodeAppSettings> nodes, CancellationToken cancellationToken)
    {
        return Task.WhenAll(nodes.Select(n => StopNodeWorkers(n, cancellationToken)));
    }

    private async Task StopNodeWorkers(NodeAppSettings node, CancellationToken nonGracefulShutdownToken)
    {
        if (!_servicesMap.TryGetValue(node, out var nodeWorkersRunner))
        {
            // It's already been stopped/removed
            return;
        }

        _logger.LogInformation("Sending instruction to stop workers for node {NodeName}", node.Name);

        try
        {
            await nodeWorkersRunner.StopAllSafe(nonGracefulShutdownToken);
            _logger.LogInformation("Node workers stopped successfully for node {NodeName}", node.Name);
        }
        catch (Exception ex)
        {
            if (ex.ShouldBeConsideredAppFatal())
            {
                _logger.LogError(ex, "Unexpected app-fatal error stopping services for node: {NodeName}. Re-throwing", node.Name);
                throw;
            }

            _logger.LogError(ex, "Unexpected error stopping services for node: {NodeName}. Now clearing up regardless", node.Name);
        }
        finally
        {
            nodeWorkersRunner.Dispose();
        }

        lock (_servicesMapLock)
        {
            _servicesMap.Remove(node);
        }
    }
}
