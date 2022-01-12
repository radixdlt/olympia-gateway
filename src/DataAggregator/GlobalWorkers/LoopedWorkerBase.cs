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
using Common.Utilities;
using NodaTime;
using System.Diagnostics;

namespace DataAggregator.GlobalWorkers;

public enum BehaviourOnFault
{
    Nothing,
    ApplicationExit,
}

public interface ILoopedWorkerBase : IHostedService, IDisposable
{
    bool IsFaulted { get; }

    public Exception? FaultedException { get; }

    bool IsStoppedSuccessfully { get; }

    bool IsCurrentlyEnabled();
}

public abstract class LoopedWorkerBase : BackgroundService, ILoopedWorkerBase
{
    public bool IsFaulted { get; private set; }


    public Exception? FaultedException { get; private set; }

    public bool IsStoppedSuccessfully { get; private set; }

    private readonly ILogger _logger;
    private readonly BehaviourOnFault _behaviourOnFault;
    private readonly LogLimiter _stillRunningLogLimiter;
    private readonly TimeSpan _minDelayBetweenLoops;
    private readonly TimeSpan _minDelayAfterErrorLoop;
    private Stopwatch? _loopIterationStopwatch;
    private bool? _wasEnabledAtLastLoopIteration;

    // ReSharper disable once ContextualLoggerProblem
    protected LoopedWorkerBase(
        ILogger logger,
        BehaviourOnFault behaviourOnFault,
        TimeSpan minDelayBetweenLoops,
        TimeSpan minDelayAfterErrorLoop,
        TimeSpan minDelayBetweenInfoLogs
    )
    {
        _logger = logger;
        _behaviourOnFault = behaviourOnFault;
        _minDelayBetweenLoops = minDelayBetweenLoops;
        _minDelayAfterErrorLoop = minDelayAfterErrorLoop;
        _stillRunningLogLimiter = new LogLimiter(minDelayBetweenInfoLogs, LogLevel.Information, LogLevel.Debug);
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            var isCurrentlyEnabled = IsCurrentlyEnabled();
            _wasEnabledAtLastLoopIteration = isCurrentlyEnabled;
            await OnStartRequested(cancellationToken, isCurrentlyEnabled);
            await base.StartAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            TrackFatalWorkerException(false, ex, "startup");
            throw;
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await OnStopRequested(cancellationToken);
            await base.StopAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            TrackFatalWorkerException(true, ex, "requested shutdown");
            throw;
        }
    }

    public virtual bool IsCurrentlyEnabled()
    {
        return true;
    }

    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        try
        {
            await OnStart(cancellationToken, IsCurrentlyEnabled());
        }
        catch (Exception ex)
        {
            TrackFatalWorkerException(false, ex, "the on start callback");
            throw;
        }

        try
        {
            await RunLoopWhilstNotCancelled(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            TrackFatalWorkerException(false, ex, "the main execution loop");
            throw;
        }

        try
        {
            await OnStoppedSuccessfully(); // Don't pass the cancellation token because it's already cancelled!
            IsStoppedSuccessfully = true;
        }
        catch (Exception ex)
        {
            TrackFatalWorkerException(true, ex, "the on stopped successfully callback");
            throw;
        }
    }

    protected virtual TimeSpan GetRemainingRestartDelay()
    {
        var timespan = _minDelayBetweenLoops - _loopIterationStopwatch!.Elapsed;
        return timespan < TimeSpan.Zero ? TimeSpan.Zero : timespan;
    }

    protected virtual TimeSpan GetRemainingRestartAfterErrorDelay()
    {
        var timespan = _minDelayAfterErrorLoop - _loopIterationStopwatch!.Elapsed;
        return timespan < TimeSpan.Zero ? TimeSpan.Zero : timespan;
    }

    protected abstract Task DoWork(CancellationToken cancellationToken);

    /// <summary>
    ///  If this errors, the Worker is faulted.
    /// </summary>
    protected virtual Task OnStart(CancellationToken cancellationToken, bool isCurrentlyEnabled)
    {
        return Task.CompletedTask;
    }

    /// <summary>
    ///  If this errors, the Worker is faulted.
    /// </summary>
    protected virtual Task OnStartRequested(CancellationToken cancellationToken, bool isCurrentlyEnabled)
    {
        _logger.Log(
            _stillRunningLogLimiter.GetLogLevel(),
            "Start requested at: {Time}. Service enabled status: {EnabledStatus}",
            SystemClock.Instance.GetCurrentInstant().AsUtcIsoDateToSecondsForLogs(),
            isCurrentlyEnabled ? "ENABLED" : "DISABLED"
        );
        return Task.CompletedTask;
    }

    /// <summary>
    ///  If this errors, the Worker is faulted.
    /// </summary>
    protected virtual Task OnStopRequested(CancellationToken nonGracefulShutdownToken)
    {
        _logger.LogInformation(
            "{GracefulState} stop requested. Stopping at: {Time}",
            nonGracefulShutdownToken.IsCancellationRequested ? "Non-graceful" : "Graceful",
            SystemClock.Instance.GetCurrentInstant().AsUtcIsoDateToSecondsForLogs()
        );
        return Task.CompletedTask;
    }

    /// <summary>
    ///  If this errors, the Worker is faulted.
    /// </summary>
    protected virtual Task OnStoppedSuccessfully()
    {
        _logger.LogInformation("Stopped successfully at: {Time}",  SystemClock.Instance.GetCurrentInstant().AsUtcIsoDateToSecondsForLogs());
        return Task.CompletedTask;
    }

    private async Task RunLoopWhilstNotCancelled(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            _loopIterationStopwatch = Stopwatch.StartNew();
            try
            {
                await ExecuteLoopIteration(cancellationToken);
                var remainingTime = GetRemainingRestartDelay();
                if (remainingTime > TimeSpan.Zero)
                {
                    await Task.Delay(remainingTime, cancellationToken);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                if (ex.ShouldBeConsideredAppFatal())
                {
                    _logger.LogError(ex, "An app-fatal error occurred. Rethrowing...");
                    throw;
                }

                // Whilst catching/handling all exceptions is typically incorrect, there are many exceptions that can
                // be thrown by HttpClients and Npgsql, and it is safer to assume that any exceptions that bubble up
                // to here are not state corrupting, than risk missing to catch a transient exception here, and causing
                // a key Worker to crash.
                // If only fatally failing on known System errors is good enough for ASP.NET Core (eg during creating
                // an API call response), it's good enough for us.

                var remainingTime = GetRemainingRestartAfterErrorDelay();
                _logger.LogError(ex, "An error occurred. Will restart work in {Delay}ms", remainingTime.Milliseconds);
                if (remainingTime > TimeSpan.Zero)
                {
                    await Task.Delay(remainingTime, cancellationToken);
                }
            }
        }
    }

    private async Task ExecuteLoopIteration(CancellationToken cancellationToken)
    {
        var isEnabled = IsCurrentlyEnabled();
        var wasLastEnabled = _wasEnabledAtLastLoopIteration;
        _wasEnabledAtLastLoopIteration = isEnabled;
        if (isEnabled)
        {
            if (wasLastEnabled == false)
            {
                _logger.LogInformation("Detected as re-enabled at {Time}, service will start doing work in a loop again", SystemClock.Instance.GetCurrentInstant().AsUtcIsoDateToSecondsForLogs());
            }

            _logger.Log(_stillRunningLogLimiter.GetLogLevel(),  "Still running at {Time}", SystemClock.Instance.GetCurrentInstant().AsUtcIsoDateToSecondsForLogs());
            await DoWork(cancellationToken);
        }
        else
        {
            if (wasLastEnabled == true)
            {
                _logger.LogInformation("Detected as disabled at {Time}. Service won't do work till re-enabled", SystemClock.Instance.GetCurrentInstant().AsUtcIsoDateToSecondsForLogs());
            }
        }
    }

    private void TrackFatalWorkerException(bool isStopRequested, Exception ex, string lifeCycleDescription)
    {
        FaultedException = ex;
        IsFaulted = true;

        if (isStopRequested)
        {
            if (ex is OperationCanceledException)
            {
                _logger.LogDebug(
                    ex,
                    "Expected operation cancelled exception whilst worker stopping during {LifeCycleDescription}",
                    lifeCycleDescription
                );
            }

            _logger.LogWarning(
                ex,
                "Unexpected exception whist worker stopping during {LifeCycleDescription}",
                lifeCycleDescription
            );
        }

        // This should never happen in the execute loop. If this happens, this is likely a failure of the LoopedWorkerBase
        // class to properly catch Exceptions.

        // Some workers (eg node workers) can get restarted as they're run by the NodeWorkersRunner.
        // Global services can't, and this will need to trigger an application exit in order to get restarted.
        if (_behaviourOnFault == BehaviourOnFault.ApplicationExit)
        {
            _logger.LogCritical(
                ex,
                "THE PROCESS WILL BE SHUTDOWN. Crucial worker crashed unexpectedly during {LifeCycleDescription}, and the worker was configured to cause the application to exit so that it can be restarted automatically",
                lifeCycleDescription
            );
            Environment.Exit(1);
        }
        else
        {
            _logger.LogError(
                ex,
                "Worker failed fatally and unexpectedly during {LifeCycleDescription}",
                lifeCycleDescription
            );
        }
    }
}
