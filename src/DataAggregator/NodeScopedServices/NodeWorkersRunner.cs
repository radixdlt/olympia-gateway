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

using Common.Exceptions;
using Common.Extensions;
using DataAggregator.NodeScopedWorkers;
using NodaTime;

namespace DataAggregator.NodeScopedServices;

public enum NodeWorkersRunnerStatus
{
    Uninitialized,
    Initializing,
    Initialized,
    Starting,
    Running,
    Stopping,
    Stopped,
}

/// <summary>
/// Note - this is created directly and not injected by DI - as it manages the NodeScope as well as the workers.
/// </summary>
public class NodeWorkersRunner : IDisposable
{
    public NodeWorkersRunnerStatus Status
    {
        get => _status;
        private set
        {
            _lastStatusChange = SystemClock.Instance.GetCurrentInstant();
            _status = value;
        }
    }

    private readonly List<INodeInitializer> _initializers;

    private readonly List<INodeWorker> _workers;

    private readonly object _statusLock = new();

    private readonly ILogger<NodeWorkersRunner> _logger;

    private IServiceScope? _nodeDependencyInjectionScope;

    private Instant _lastStatusChange;

    // Items needing disposal
    private CancellationTokenSource? _cancellationTokenSource;
    private CancellationTokenSource? _combinedInitializeCancellationTokenSource;
    private CancellationTokenRegistration? _runningWorkersCancellationTokenRegistration;
    private IDisposable? _logScope;
    private NodeWorkersRunnerStatus _status;

    public NodeWorkersRunner(ILogger<NodeWorkersRunner> logger, IServiceScope nodeDependencyInjectionScope, IDisposable logScope)
    {
        _logger = logger;
        _nodeDependencyInjectionScope = nodeDependencyInjectionScope;
        _logScope = logScope;
        _cancellationTokenSource = new CancellationTokenSource();
        _initializers = nodeDependencyInjectionScope.ServiceProvider.GetServices<INodeInitializer>().ToList();
        _workers = nodeDependencyInjectionScope.ServiceProvider.GetServices<INodeWorker>().ToList();
        Status = NodeWorkersRunnerStatus.Uninitialized;
    }

    /// <summary>
    /// If this isn't true, at least one worker has crashed - NodeWorkersRunner needs to be stopped, recreated and restarted.
    /// </summary>
    public bool IsHealthy()
    {
        const int GraceSecondsBeforeMarkingStalled = 10;

        var isRunningOrNotStalled = Status == NodeWorkersRunnerStatus.Running || _lastStatusChange.WithinPeriodOfNow(Duration.FromSeconds(GraceSecondsBeforeMarkingStalled));
        if (!isRunningOrNotStalled)
        {
            _logger.LogWarning(
                "Marked as unhealthy because current status is {Status} and last status changes was at {LastStatusChange}, longer than {GracePeriod}s ago - suggesting that the WorkersRegistry hasn't properly handled something, and these NodeWorkers should be restarted",
                Status,
                _lastStatusChange,
                GraceSecondsBeforeMarkingStalled
            );
            return false;
        }

        var allWorkersAreHealthy = _workers.All(w => !w.IsFaulted && !w.IsStoppedSuccessfully);
        if (!allWorkersAreHealthy)
        {
            _logger.LogWarning(
                "Marked as unhealthy because at least one worker is faulted or stopped, so these NodeWorkers should be restarted by the WorkersRegistry. Worker states: {WorkerStates}",
                string.Join(", ", _workers.Select(w => $"{w.GetType().Name}: [Faulted={w.IsFaulted}, Exception={w.FaultedException?.GetType().Name ?? "None"}, Stopped={w.IsStoppedSuccessfully}]"))
            );

            var appFatalFaultedExceptions = _workers
                .SelectNonNull(w => w.FaultedException)
                .Where(w => w.ShouldBeConsideredAppFatal())
                .ToList();

            if (appFatalFaultedExceptions.Any())
            {
                throw new AppFatalExceptionDetectedException(appFatalFaultedExceptions.First());
            }

            return false;
        }

        return true;
    }

    /// <summary>
    ///  Runs all INodeInitializers and waits for them to complete.
    ///  Should be awaited before workers are started. Can throw if initialization fails.
    ///  If this throws, it is the caller's duty to call StopWorkersSafe or Dispose().
    /// </summary>
    public async Task Initialize(CancellationToken cancellationToken)
    {
        lock (_statusLock)
        {
            switch (Status)
            {
                case NodeWorkersRunnerStatus.Uninitialized:
                    break; // The good case
                case NodeWorkersRunnerStatus.Initializing:
                case NodeWorkersRunnerStatus.Initialized:
                case NodeWorkersRunnerStatus.Starting:
                case NodeWorkersRunnerStatus.Running:
                case NodeWorkersRunnerStatus.Stopping:
                case NodeWorkersRunnerStatus.Stopped:
                    throw new Exception("Node set-up has already been initialized");
                default:
                    throw new ArgumentOutOfRangeException();
            }

            Status = NodeWorkersRunnerStatus.Initializing;
        }

        _combinedInitializeCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var combinedCancellationToken = _combinedInitializeCancellationTokenSource.Token;

        try
        {
            await Task.WhenAll(_initializers.Select(i => i.Initialize(combinedCancellationToken)));
        }
        catch (Exception ex)
        {
            _logger.LogInformation(ex, "At least one initializer errored - all workers for the node will now be stopped");
            await StopAllSafe(CancellationToken.None);
            throw;
        }

        lock (_statusLock)
        {
            switch (Status)
            {
                case NodeWorkersRunnerStatus.Uninitialized:
                case NodeWorkersRunnerStatus.Initializing:
                    Status = NodeWorkersRunnerStatus.Initialized;
                    return;
                case NodeWorkersRunnerStatus.Initialized:
                case NodeWorkersRunnerStatus.Starting:
                case NodeWorkersRunnerStatus.Running:
                case NodeWorkersRunnerStatus.Stopping:
                case NodeWorkersRunnerStatus.Stopped:
                    return; // Don't change state back
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }
    }

    /// <summary>
    ///  Starts all workers. Throws if called more than once.
    /// </summary>
    public async Task StartWorkers(CancellationToken cancellationToken)
    {
        lock (_statusLock)
        {
            switch (Status)
            {
                case NodeWorkersRunnerStatus.Uninitialized:
                case NodeWorkersRunnerStatus.Initializing:
                    throw new Exception("Should be initialized first");
                case NodeWorkersRunnerStatus.Initialized:
                    break; // The good case
                case NodeWorkersRunnerStatus.Starting:
                case NodeWorkersRunnerStatus.Running:
                case NodeWorkersRunnerStatus.Stopping:
                case NodeWorkersRunnerStatus.Stopped:
                    throw new Exception("Workers have already been started");
                default:
                    throw new ArgumentOutOfRangeException();
            }

            Status = NodeWorkersRunnerStatus.Starting;
        }

        // If the cancellation token goes off,
#pragma warning disable CS4014 // Cannot await StopAllSafe
        _runningWorkersCancellationTokenRegistration = cancellationToken.Register(() => StopAllSafe(CancellationToken.None));
#pragma warning restore CS4014

        try
        {
            await Task.WhenAll(_workers.Select(w => w.StartAsync(cancellationToken)));
        }
        catch (Exception ex)
        {
            _logger.LogInformation(ex, "At least one worker start errored - all workers for the node will now be stopped");
            await StopAllSafe(CancellationToken.None);
            throw;
        }

        lock (_statusLock)
        {
            switch (Status)
            {
                case NodeWorkersRunnerStatus.Uninitialized:
                case NodeWorkersRunnerStatus.Initializing:
                case NodeWorkersRunnerStatus.Initialized:
                case NodeWorkersRunnerStatus.Starting:
                    Status = NodeWorkersRunnerStatus.Running;
                    return;
                case NodeWorkersRunnerStatus.Running:
                case NodeWorkersRunnerStatus.Stopping:
                case NodeWorkersRunnerStatus.Stopped:
                    return; // Don't change state back
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }
    }

    /// <summary>
    ///  Stops all workers. It's safe to call this multiple times.
    /// </summary>
    public async Task StopAllSafe(CancellationToken nonGracefulShutdownToken = default)
    {
        lock (_statusLock)
        {
            switch (Status)
            {
                case NodeWorkersRunnerStatus.Uninitialized:
                case NodeWorkersRunnerStatus.Initialized:
                    Status = NodeWorkersRunnerStatus.Stopped;
                    return;
                case NodeWorkersRunnerStatus.Initializing:
                case NodeWorkersRunnerStatus.Starting:
                    Status = NodeWorkersRunnerStatus.Stopping;
                    SafelyCancelInitializationOrStartup();
                    break;
                case NodeWorkersRunnerStatus.Running:
                    Status = NodeWorkersRunnerStatus.Stopping;
                    break;
                case NodeWorkersRunnerStatus.Stopping:
                    break;
                case NodeWorkersRunnerStatus.Stopped:
                    return;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        try
        {
            // StopAsync should be safe to be called multiple times, and will wait till the service stops
            await Task.WhenAll(_workers.Select(w => w.StopAsync(nonGracefulShutdownToken)));
        }
        catch (Exception ex)
        {
            _logger.LogInformation(ex, "Workers errored when they tried to be stopped. Proceeding under the assumption they were stopped successfully");
        }

        lock (_statusLock)
        {
            Status = NodeWorkersRunnerStatus.Stopped;
        }
    }

    public void Dispose()
    {
        _logger.LogDebug("Disposing...");

        if (Status != NodeWorkersRunnerStatus.Stopped)
        {
            _logger.LogError("Dispose() was called before the workers were stopped - the workers may continue to run");
        }

        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = null;
        _nodeDependencyInjectionScope?.Dispose();
        _nodeDependencyInjectionScope = null;
        _combinedInitializeCancellationTokenSource?.Dispose();
        _combinedInitializeCancellationTokenSource = null;
        _runningWorkersCancellationTokenRegistration?.Dispose();
        _runningWorkersCancellationTokenRegistration = null;
        _logScope?.Dispose();
        _logScope = null;
        GC.SuppressFinalize(this);
    }

    private void SafelyCancelInitializationOrStartup()
    {
        try
        {
            _cancellationTokenSource?.Cancel();
        }
        catch (AggregateException ex)
        {
            _logger.LogInformation(ex, "Errors thrown whilst cancelling initialization or startup");
        }
    }
}
