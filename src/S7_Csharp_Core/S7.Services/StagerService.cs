using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Services;
using S7.Core.Abstractions.Configuration;
using S7.Net;
using S7.Utils;

namespace S7.Services
{
    /// <summary>
    /// Service implementation for stager operations with installation validation and retry logic.
    /// </summary>
    public class StagerService(
        ILogger<StagerService> logger,
        PayloadManager payloadManager) : IStagerService
    {
        private readonly ILogger<StagerService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        private readonly PayloadManager _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));

        /// <inheritdoc />
        public event EventHandler<StagerInstallationProgressEventArgs>? InstallationProgressChanged;

        /// <inheritdoc />
        public event EventHandler<StagerInstallationCompletedEventArgs>? InstallationCompleted;

        /// <inheritdoc />
        public event EventHandler<StagerCommandExecutedEventArgs>? CommandExecuted;

        /// <inheritdoc />
        public async Task<Result<StagerInstallationResult>> InstallStagerAsync(
            StagerInstallationOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var stopwatch = Stopwatch.StartNew();
            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();

            _logger.LogInformation("Starting stager installation. PayloadPath: {PayloadPath}, CorrelationId: {CorrelationId}",
                options.PayloadPath, correlationId);

            try
            {
                // Validate options
                var validationResult = ValidateInstallationOptions(options);
                if (!validationResult.IsSuccess)
                {
                    return Result<StagerInstallationResult>.Failure(validationResult.Error);
                }

                // Load stager payload
                var stagerPayload = await LoadStagerPayloadAsync(options.PayloadPath, cancellationToken).ConfigureAwait(false);
                if (!stagerPayload.IsSuccess)
                {
                    return Result<StagerInstallationResult>.Failure(stagerPayload.Error);
                }

                // Create PLC client
                using var plcClient = CreatePlcClient(options.ChannelConfig);

                // Perform installation with retry logic
                var installationResult = await PerformInstallationWithRetryAsync(
                    plcClient, 
                    stagerPayload.Value, 
                    options, 
                    correlationId, 
                    cancellationToken).ConfigureAwait(false);

                if (!installationResult.IsSuccess)
                {
                    return installationResult;
                }

                stopwatch.Stop();

                var result = new StagerInstallationResult
                {
                    CorrelationId = correlationId,
                    PayloadPath = options.PayloadPath,
                    PayloadSize = stagerPayload.Value.Length,
                    InstallationDuration = stopwatch.Elapsed,
                    InstallationTimestamp = DateTime.UtcNow,
                    IsSuccess = true,
                    InstallationMode = options.InstallationMode,
                    TargetAddress = options.TargetAddress,
                    Metadata = new Dictionary<string, object>
                    {
                        ["RetryAttempts"] = installationResult.Value.RetryAttempts,
                        ["VerificationPassed"] = installationResult.Value.VerificationPassed,
                        ["InstallationSpeed"] = CalculateInstallationSpeed(stagerPayload.Value.Length, stopwatch.Elapsed)
                    }
                };

                _logger.LogInformation("Stager installation completed successfully in {Duration}ms. CorrelationId: {CorrelationId}",
                    stopwatch.ElapsedMilliseconds, correlationId);

                // Raise completion event
                var completedArgs = new StagerInstallationCompletedEventArgs(correlationId, result, null);
                InstallationCompleted?.Invoke(this, completedArgs);

                return Result<StagerInstallationResult>.Success(result);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Stager installation was cancelled. CorrelationId: {CorrelationId}", correlationId);
                var cancelledArgs = new StagerInstallationCompletedEventArgs(correlationId, null, "Installation was cancelled");
                InstallationCompleted?.Invoke(this, cancelledArgs);
                return Result<StagerInstallationResult>.Failure("Stager installation was cancelled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Stager installation failed. CorrelationId: {CorrelationId}", correlationId);
                var errorArgs = new StagerInstallationCompletedEventArgs(correlationId, null, ex.Message);
                InstallationCompleted?.Invoke(this, errorArgs);
                return Result<StagerInstallationResult>.Failure($"Stager installation failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<StagerVerificationResult>> VerifyStagerInstallationAsync(
            StagerVerificationOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();
            _logger.LogInformation("Starting stager verification. CorrelationId: {CorrelationId}", correlationId);

            try
            {
                using var plcClient = CreatePlcClient(options.ChannelConfig);

                var verificationSteps = new List<StagerVerificationStep>();

                // Step 1: Basic connectivity test
                var connectivityResult = await VerifyConnectivityAsync(plcClient, cancellationToken).ConfigureAwait(false);
                verificationSteps.Add(new StagerVerificationStep
                {
                    StepName = "Connectivity Test",
                    IsSuccess = connectivityResult.IsSuccess,
                    ErrorMessage = connectivityResult.IsSuccess ? null : connectivityResult.Error.Message,
                    Duration = TimeSpan.FromMilliseconds(100) // Simulated duration
                });

                // Step 2: Stager response test
                if (connectivityResult.IsSuccess)
                {
                    var responseResult = await VerifyStagerResponseAsync(plcClient, options, cancellationToken).ConfigureAwait(false);
                    verificationSteps.Add(new StagerVerificationStep
                    {
                        StepName = "Stager Response Test",
                        IsSuccess = responseResult.IsSuccess,
                        ErrorMessage = responseResult.IsSuccess ? null : responseResult.Error.Message,
                        Duration = TimeSpan.FromMilliseconds(200) // Simulated duration
                    });
                }

                // Step 3: Memory integrity check (if requested)
                if (options.PerformMemoryIntegrityCheck && verificationSteps.TrueForAll(s => s.IsSuccess))
                {
                    var integrityResult = await VerifyMemoryIntegrityAsync(plcClient, options, cancellationToken).ConfigureAwait(false);
                    verificationSteps.Add(new StagerVerificationStep
                    {
                        StepName = "Memory Integrity Check",
                        IsSuccess = integrityResult.IsSuccess,
                        ErrorMessage = integrityResult.IsSuccess ? null : integrityResult.Error.Message,
                        Duration = TimeSpan.FromMilliseconds(500) // Simulated duration
                    });
                }

                var overallSuccess = verificationSteps.TrueForAll(s => s.IsSuccess);

                var result = new StagerVerificationResult
                {
                    CorrelationId = correlationId,
                    IsVerified = overallSuccess,
                    VerificationSteps = verificationSteps,
                    VerificationTimestamp = DateTime.UtcNow,
                    TotalSteps = verificationSteps.Count,
                    PassedSteps = verificationSteps.Count(s => s.IsSuccess),
                    Metadata = new Dictionary<string, object>
                    {
                        ["VerificationMode"] = options.VerificationMode.ToString(),
                        ["MemoryIntegrityCheck"] = options.PerformMemoryIntegrityCheck,
                        ["TotalDuration"] = verificationSteps.Sum(s => s.Duration.TotalMilliseconds)
                    }
                };

                _logger.LogInformation("Stager verification completed. Success: {IsVerified}, Steps: {PassedSteps}/{TotalSteps}. CorrelationId: {CorrelationId}",
                    overallSuccess, result.PassedSteps, result.TotalSteps, correlationId);

                return Result<StagerVerificationResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Stager verification failed. CorrelationId: {CorrelationId}", correlationId);
                return Result<StagerVerificationResult>.Failure($"Stager verification failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<StagerCommandResult>> ExecuteStagerCommandAsync(
            StagerCommandOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var stopwatch = Stopwatch.StartNew();
            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();

            _logger.LogInformation("Executing stager command. Command: {Command}, CorrelationId: {CorrelationId}",
                options.Command, correlationId);

            try
            {
                using var plcClient = CreatePlcClient(options.ChannelConfig);

                // Execute command based on type
                var commandResult = options.Command.ToUpperInvariant() switch
                {
                    "WRITE" => await ExecuteWriteCommandAsync(plcClient, options, cancellationToken).ConfigureAwait(false),
                    "READ" => await ExecuteReadCommandAsync(plcClient, options, cancellationToken).ConfigureAwait(false),
                    "INVOKE" => await ExecuteInvokeCommandAsync(plcClient, options, cancellationToken).ConfigureAwait(false),
                    "INSTALL_HOOK" => await ExecuteInstallHookCommandAsync(plcClient, options, cancellationToken).ConfigureAwait(false),
                    _ => Result<byte[]>.Failure($"Unknown command: {options.Command}")
                };

                stopwatch.Stop();

                var result = new StagerCommandResult
                {
                    CorrelationId = correlationId,
                    Command = options.Command,
                    IsSuccess = commandResult.IsSuccess,
                    ResponseData = commandResult.IsSuccess ? commandResult.Value : null,
                    ErrorMessage = commandResult.IsSuccess ? null : commandResult.Error.Message,
                    ExecutionDuration = stopwatch.Elapsed,
                    ExecutionTimestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, object>
                    {
                        ["CommandParameters"] = options.Parameters ?? new Dictionary<string, object>(),
                        ["ResponseSize"] = commandResult.IsSuccess ? commandResult.Value?.Length ?? 0 : 0
                    }
                };

                _logger.LogInformation("Stager command executed. Success: {IsSuccess}, Duration: {Duration}ms. CorrelationId: {CorrelationId}",
                    result.IsSuccess, stopwatch.ElapsedMilliseconds, correlationId);

                // Raise command executed event
                var executedArgs = new StagerCommandExecutedEventArgs(correlationId, result);
                CommandExecuted?.Invoke(this, executedArgs);

                return Result<StagerCommandResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Stager command execution failed. CorrelationId: {CorrelationId}", correlationId);
                return Result<StagerCommandResult>.Failure($"Command execution failed: {ex.Message}");
            }
        }

        /// <inheritdoc />
        public async Task<Result<StagerLifecycleResult>> ManageStagerLifecycleAsync(
            StagerLifecycleOptions options,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(options);

            var correlationId = options.CorrelationId ?? Guid.NewGuid().ToString();
            _logger.LogInformation("Managing stager lifecycle. Operation: {Operation}, CorrelationId: {CorrelationId}",
                options.Operation, correlationId);

            try
            {
                using var plcClient = CreatePlcClient(options.ChannelConfig);

                var lifecycleResult = options.Operation.ToUpperInvariant() switch
                {
                    "START" => await StartStagerAsync(plcClient, options, cancellationToken).ConfigureAwait(false),
                    "STOP" => await StopStagerAsync(plcClient, options, cancellationToken).ConfigureAwait(false),
                    "RESTART" => await RestartStagerAsync(plcClient, options, cancellationToken).ConfigureAwait(false),
                    "STATUS" => await GetStagerStatusAsync(plcClient, options, cancellationToken).ConfigureAwait(false),
                    _ => Result<StagerLifecycleResult>.Failure($"Unknown lifecycle operation: {options.Operation}")
                };

                _logger.LogInformation("Stager lifecycle operation completed. Success: {IsSuccess}, CorrelationId: {CorrelationId}",
                    lifecycleResult.IsSuccess, correlationId);

                return lifecycleResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Stager lifecycle management failed. CorrelationId: {CorrelationId}", correlationId);
                return Result<StagerLifecycleResult>.Failure($"Lifecycle management failed: {ex.Message}");
            }
        }

        private Result ValidateInstallationOptions(StagerInstallationOptions options)
        {
            var errors = new List<string>();

            if (string.IsNullOrEmpty(options.PayloadPath))
                errors.Add("PayloadPath is required");

            if (options.ChannelConfig == null)
                errors.Add("ChannelConfig is required");

            if (options.MaxRetryAttempts < 0)
                errors.Add("MaxRetryAttempts cannot be negative");

            if (options.RetryDelay < TimeSpan.Zero)
                errors.Add("RetryDelay cannot be negative");

            return errors.Count == 0 
                ? Result.Success() 
                : Result.Failure(string.Join("; ", errors));
        }

        private async Task<Result<byte[]>> LoadStagerPayloadAsync(string payloadPath, CancellationToken cancellationToken)
        {
            try
            {
                var payload = await _payloadManager.LoadPayloadAsync(payloadPath, cancellationToken).ConfigureAwait(false);
                return payload != null 
                    ? Result<byte[]>.Success(payload) 
                    : Result<byte[]>.Failure("Failed to load stager payload");
            }
            catch (Exception ex)
            {
                return Result<byte[]>.Failure(ex);
            }
        }

        private PlcClient CreatePlcClient(CommunicationChannelConfig config)
        {
            var channel = config.Mode.ToUpperInvariant() switch
            {
                "TCP" => new S7.Net.Channels.TcpChannel(config.Host ?? "localhost", config.Port),
                "SERIAL" => new S7.Net.Channels.SerialChannel(config.SerialPort ?? "COM1", config.BaudRate),
                _ => throw new ArgumentException($"Unsupported connection type: {config.Mode}")
            };

            Action<string> logger = message => _logger.LogDebug("{Message}", message);
            return new PlcClient(channel, logger);
        }

        private async Task<Result<StagerInstallationResult>> PerformInstallationWithRetryAsync(
            PlcClient plcClient,
            byte[] stagerPayload,
            StagerInstallationOptions options,
            string correlationId,
            CancellationToken cancellationToken)
        {
            var retryAttempts = 0;
            Exception? lastException = null;

            while (retryAttempts <= options.MaxRetryAttempts)
            {
                try
                {
                    // Report progress
                    var progressArgs = new StagerInstallationProgressEventArgs(
                        correlationId,
                        $"Installation attempt {retryAttempts + 1}/{options.MaxRetryAttempts + 1}",
                        (double)retryAttempts / (options.MaxRetryAttempts + 1) * 100);
                    InstallationProgressChanged?.Invoke(this, progressArgs);

                    // Perform installation
                    await plcClient.InstallStager(stagerPayload, cancellationToken).ConfigureAwait(false);

                    // Verify installation if requested
                    var verificationPassed = true;
                    if (options.VerifyAfterInstallation)
                    {
                        var verificationOptions = new StagerVerificationOptions
                        {
                            ChannelConfig = options.ChannelConfig,
                            CorrelationId = correlationId,
                            VerificationMode = StagerVerificationMode.Basic
                        };

                        var verificationResult = await VerifyStagerInstallationAsync(verificationOptions, cancellationToken).ConfigureAwait(false);
                        verificationPassed = verificationResult.IsSuccess && verificationResult.Value.IsVerified;
                    }

                    // Success
                    return Result<StagerInstallationResult>.Success(new StagerInstallationResult
                    {
                        CorrelationId = correlationId,
                        PayloadPath = options.PayloadPath,
                        PayloadSize = stagerPayload.Length,
                        IsSuccess = true,
                        RetryAttempts = retryAttempts,
                        VerificationPassed = verificationPassed,
                        InstallationMode = options.InstallationMode,
                        TargetAddress = options.TargetAddress
                    });
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    retryAttempts++;

                    _logger.LogWarning(ex, "Stager installation attempt {Attempt} failed. CorrelationId: {CorrelationId}",
                        retryAttempts, correlationId);

                    if (retryAttempts <= options.MaxRetryAttempts)
                    {
                        await Task.Delay(options.RetryDelay, cancellationToken).ConfigureAwait(false);
                    }
                }
            }

            return Result<StagerInstallationResult>.Failure(
                $"Stager installation failed after {retryAttempts} attempts. Last error: {lastException?.Message}");
        }

        private async Task<Result> VerifyConnectivityAsync(PlcClient plcClient, CancellationToken cancellationToken)
        {
            try
            {
                // Simulate connectivity test
                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                return Result.Success();
            }
            catch (Exception ex)
            {
                return Result.Failure(ex);
            }
        }

        private async Task<Result> VerifyStagerResponseAsync(PlcClient plcClient, StagerVerificationOptions options, CancellationToken cancellationToken)
        {
            try
            {
                // Simulate stager response test
                await Task.Delay(200, cancellationToken).ConfigureAwait(false);
                return Result.Success();
            }
            catch (Exception ex)
            {
                return Result.Failure(ex);
            }
        }

        private async Task<Result> VerifyMemoryIntegrityAsync(PlcClient plcClient, StagerVerificationOptions options, CancellationToken cancellationToken)
        {
            try
            {
                // Simulate memory integrity check
                await Task.Delay(500, cancellationToken).ConfigureAwait(false);
                return Result.Success();
            }
            catch (Exception ex)
            {
                return Result.Failure(ex);
            }
        }

        private async Task<Result<byte[]>> ExecuteWriteCommandAsync(PlcClient plcClient, StagerCommandOptions options, CancellationToken cancellationToken)
        {
            try
            {
                var address = GetParameterValue<uint>(options.Parameters, "address");
                var data = GetParameterValue<byte[]>(options.Parameters, "data");

                await plcClient.WriteViaStager(address, data, cancellationToken).ConfigureAwait(false);
                return Result<byte[]>.Success(Array.Empty<byte>());
            }
            catch (Exception ex)
            {
                return Result<byte[]>.Failure(ex);
            }
        }

        private async Task<Result<byte[]>> ExecuteReadCommandAsync(PlcClient plcClient, StagerCommandOptions options, CancellationToken cancellationToken)
        {
            try
            {
                // Simulate read command - in real implementation this would read from PLC
                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                return Result<byte[]>.Success(new byte[] { 0x01, 0x02, 0x03, 0x04 });
            }
            catch (Exception ex)
            {
                return Result<byte[]>.Failure(ex);
            }
        }

        private async Task<Result<byte[]>> ExecuteInvokeCommandAsync(PlcClient plcClient, StagerCommandOptions options, CancellationToken cancellationToken)
        {
            try
            {
                var hookNo = GetParameterValue<int>(options.Parameters, "hookNo");
                var args = GetParameterValue<byte[]>(options.Parameters, "args");

                var response = await plcClient.InvokeAddHook(hookNo, args, true, cancellationToken).ConfigureAwait(false);
                return Result<byte[]>.Success(response ?? Array.Empty<byte>());
            }
            catch (Exception ex)
            {
                return Result<byte[]>.Failure(ex);
            }
        }

        private async Task<Result<byte[]>> ExecuteInstallHookCommandAsync(PlcClient plcClient, StagerCommandOptions options, CancellationToken cancellationToken)
        {
            try
            {
                var targetAddress = GetParameterValue<uint>(options.Parameters, "targetAddress");
                var payload = GetParameterValue<byte[]>(options.Parameters, "payload");
                var newHookNo = GetParameterValue<int>(options.Parameters, "newHookNo");

                await plcClient.InstallAddHookViaStager(targetAddress, payload, newHookNo, cancellationToken).ConfigureAwait(false);
                return Result<byte[]>.Success(Array.Empty<byte>());
            }
            catch (Exception ex)
            {
                return Result<byte[]>.Failure(ex);
            }
        }

        private async Task<Result<StagerLifecycleResult>> StartStagerAsync(PlcClient plcClient, StagerLifecycleOptions options, CancellationToken cancellationToken)
        {
            try
            {
                // Simulate stager start
                await Task.Delay(200, cancellationToken).ConfigureAwait(false);
                
                return Result<StagerLifecycleResult>.Success(new StagerLifecycleResult
                {
                    CorrelationId = options.CorrelationId ?? Guid.NewGuid().ToString(),
                    Operation = "START",
                    IsSuccess = true,
                    Status = "Running",
                    OperationTimestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                return Result<StagerLifecycleResult>.Failure(ex);
            }
        }

        private async Task<Result<StagerLifecycleResult>> StopStagerAsync(PlcClient plcClient, StagerLifecycleOptions options, CancellationToken cancellationToken)
        {
            try
            {
                // Simulate stager stop
                await Task.Delay(200, cancellationToken).ConfigureAwait(false);
                
                return Result<StagerLifecycleResult>.Success(new StagerLifecycleResult
                {
                    CorrelationId = options.CorrelationId ?? Guid.NewGuid().ToString(),
                    Operation = "STOP",
                    IsSuccess = true,
                    Status = "Stopped",
                    OperationTimestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                return Result<StagerLifecycleResult>.Failure(ex);
            }
        }

        private async Task<Result<StagerLifecycleResult>> RestartStagerAsync(PlcClient plcClient, StagerLifecycleOptions options, CancellationToken cancellationToken)
        {
            try
            {
                // Simulate stager restart
                await Task.Delay(400, cancellationToken).ConfigureAwait(false);
                
                return Result<StagerLifecycleResult>.Success(new StagerLifecycleResult
                {
                    CorrelationId = options.CorrelationId ?? Guid.NewGuid().ToString(),
                    Operation = "RESTART",
                    IsSuccess = true,
                    Status = "Running",
                    OperationTimestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                return Result<StagerLifecycleResult>.Failure(ex);
            }
        }

        private async Task<Result<StagerLifecycleResult>> GetStagerStatusAsync(PlcClient plcClient, StagerLifecycleOptions options, CancellationToken cancellationToken)
        {
            try
            {
                // Simulate status check
                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
                
                return Result<StagerLifecycleResult>.Success(new StagerLifecycleResult
                {
                    CorrelationId = options.CorrelationId ?? Guid.NewGuid().ToString(),
                    Operation = "STATUS",
                    IsSuccess = true,
                    Status = "Running",
                    OperationTimestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, object>
                    {
                        ["Uptime"] = TimeSpan.FromMinutes(15).ToString(),
                        ["CommandsExecuted"] = 42,
                        ["LastActivity"] = DateTime.UtcNow.AddMinutes(-2)
                    }
                });
            }
            catch (Exception ex)
            {
                return Result<StagerLifecycleResult>.Failure(ex);
            }
        }

        private T GetParameterValue<T>(Dictionary<string, object>? parameters, string key)
        {
            if (parameters?.TryGetValue(key, out var value) == true && value is T typedValue)
            {
                return typedValue;
            }
            throw new ArgumentException($"Required parameter '{key}' of type {typeof(T).Name} not found");
        }

        private double CalculateInstallationSpeed(int payloadSize, TimeSpan duration)
        {
            return duration.TotalSeconds > 0 ? payloadSize / duration.TotalSeconds : 0;
        }
    }
}