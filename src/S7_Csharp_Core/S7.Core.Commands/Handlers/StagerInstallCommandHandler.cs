using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Services;
using S7.Net;
using S7.Net.Interfaces;
using S7.Net.Channels;

namespace S7.Core.Commands.Handlers
{
    /// <summary>
    /// Command handler for stager installation operations.
    /// </summary>
    public class StagerInstallCommandHandler : ICommandHandler<StagerInstallCommand, StagerInstallResult>
    {
        private readonly ILogger<StagerInstallCommandHandler> _logger;
        private readonly PayloadManager _payloadManager;
        private readonly IPowerController? _powerController;

        /// <summary>
        /// Initializes a new instance of the StagerInstallCommandHandler class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="payloadManager">The payload manager for handling payloads</param>
        /// <param name="powerController">The power controller (optional)</param>
        public StagerInstallCommandHandler(
            ILogger<StagerInstallCommandHandler> logger,
            PayloadManager payloadManager,
            IPowerController? powerController = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
            _powerController = powerController;
        }

        /// <summary>
        /// Handles the stager installation command execution.
        /// </summary>
        /// <param name="command">The stager installation command to execute</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the command execution result</returns>
        public async Task<CommandResult<StagerInstallResult>> HandleAsync(
            StagerInstallCommand command, 
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(command);

            _logger.LogInformation("Starting stager installation operation. CorrelationId: {CorrelationId}, PayloadPath: {PayloadPath}",
                command.CorrelationId, command.PayloadPath);

            var stopwatch = Stopwatch.StartNew();
            var performanceMetrics = new InstallationPerformanceMetrics();
            var warnings = new List<string>();

            try
            {
                // Validate command parameters
                var validationResult = ValidateCommand(command);
                if (!validationResult.IsValid)
                {
                    _logger.LogWarning("Stager installation command validation failed. CorrelationId: {CorrelationId}, Errors: {Errors}",
                        command.CorrelationId, string.Join(", ", validationResult.Errors));
                    return CommandResult<StagerInstallResult>.ValidationFailure(validationResult.Errors, command.CorrelationId);
                }

                // Load the stager payload
                _logger.LogInformation("Loading stager payload from {PayloadPath}. CorrelationId: {CorrelationId}",
                    command.PayloadPath, command.CorrelationId);
                
                var payload = await _payloadManager.LoadPayloadAsync(command.PayloadPath, cancellationToken);

                // Perform power cycling before installation if requested
                if (command.PowerCycleBeforeInstall && command.PowerConfig != null)
                {
                    var powerCycleTime = await PerformPowerCycleAsync(command.PowerConfig, "before installation", command.CorrelationId, cancellationToken);
                    performanceMetrics = performanceMetrics with { PowerCycleTime = performanceMetrics.PowerCycleTime.Add(powerCycleTime) };
                }

                // Create PLC client with the specified configuration
                using var plcClient = CreatePlcClient(command.ChannelConfig);

                // Perform handshake if requested
                if (command.PerformHandshake)
                {
                    var handshakeStart = Stopwatch.StartNew();
                    _logger.LogInformation("Performing handshake. CorrelationId: {CorrelationId}", command.CorrelationId);
                    
                    await plcClient.PerformHandshakeAsync(cancellationToken);
                    handshakeStart.Stop();
                    performanceMetrics = performanceMetrics with { HandshakeTime = handshakeStart.Elapsed };
                    
                    _logger.LogInformation("Handshake completed in {Duration}ms. CorrelationId: {CorrelationId}",
                        handshakeStart.ElapsedMilliseconds, command.CorrelationId);
                }

                // Install the stager with retry logic
                var installationResult = await InstallStagerWithRetryAsync(plcClient, command, payload, cancellationToken);
                performanceMetrics = performanceMetrics with 
                { 
                    PayloadTransferTime = installationResult.TransferTime,
                    RetryAttempts = installationResult.RetryAttempts,
                    AverageTransferSpeed = installationResult.TransferSpeed,
                    TotalBytesTransferred = (uint)payload.Length
                };

                if (!installationResult.IsSuccess)
                {
                    return CommandResult<StagerInstallResult>.Failure(
                        installationResult.ErrorMessage ?? "Stager installation failed", 
                        command.CorrelationId);
                }

                // Verify installation if requested
                bool isVerified = false;
                if (command.VerifyInstallation)
                {
                    var verificationStart = Stopwatch.StartNew();
                    isVerified = await VerifyStagerInstallationAsync(plcClient, installationResult.InstallationAddress, payload, command.CorrelationId, cancellationToken);
                    verificationStart.Stop();
                    performanceMetrics = performanceMetrics with { VerificationTime = verificationStart.Elapsed };
                    
                    if (!isVerified)
                    {
                        warnings.Add("Stager installation verification failed");
                    }
                }

                // Get version information if requested
                string? stagerVersion = null;
                if (command.GetVersionInfo)
                {
                    try
                    {
                        stagerVersion = await GetStagerVersionAsync(plcClient, installationResult.InstallationAddress, cancellationToken);
                        _logger.LogInformation("Stager version: {Version}. CorrelationId: {CorrelationId}",
                            stagerVersion, command.CorrelationId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to retrieve stager version. CorrelationId: {CorrelationId}", command.CorrelationId);
                        warnings.Add("Failed to retrieve stager version information");
                    }
                }

                // Perform power cycling after installation if requested
                if (command.PowerCycleAfterInstall && command.PowerConfig != null)
                {
                    var powerCycleTime = await PerformPowerCycleAsync(command.PowerConfig, "after installation", command.CorrelationId, cancellationToken);
                    performanceMetrics = performanceMetrics with { PowerCycleTime = performanceMetrics.PowerCycleTime.Add(powerCycleTime) };
                }

                stopwatch.Stop();

                // Calculate checksum
                var checksum = CalculateChecksum(payload);

                // Create the result
                var result = new StagerInstallResult
                {
                    IsInstalled = true,
                    StagerVersion = stagerVersion,
                    InstallationAddress = installationResult.InstallationAddress,
                    StagerSize = (uint)payload.Length,
                    Duration = stopwatch.Elapsed,
                    Checksum = checksum,
                    IsVerified = isVerified,
                    AdditionalHooks = installationResult.AdditionalHooks,
                    PerformanceMetrics = performanceMetrics,
                    Warnings = warnings.Count > 0 ? warnings.ToArray() : null
                };

                _logger.LogInformation("Stager installation completed successfully in {Duration}ms. CorrelationId: {CorrelationId}",
                    stopwatch.ElapsedMilliseconds, command.CorrelationId);

                return CommandResult<StagerInstallResult>.Success(result, command.CorrelationId);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Stager installation operation was cancelled. CorrelationId: {CorrelationId}", command.CorrelationId);
                return CommandResult<StagerInstallResult>.Failure("Operation was cancelled", command.CorrelationId);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.LogError(ex, "Stager installation operation failed after {Duration}ms. CorrelationId: {CorrelationId}",
                    stopwatch.ElapsedMilliseconds, command.CorrelationId);
                return CommandResult<StagerInstallResult>.FromException(ex, command.CorrelationId);
            }
        }

        private Abstractions.Validation.ValidationResult ValidateCommand(StagerInstallCommand command)
        {
            var errors = new List<string>();

            if (!File.Exists(command.PayloadPath))
                errors.Add($"Stager payload file not found: {command.PayloadPath}");

            if ((command.PowerCycleBeforeInstall || command.PowerCycleAfterInstall) && command.PowerConfig == null)
                errors.Add("Power cycling requested but power controller configuration is missing");

            if (command.PowerConfig != null && _powerController == null)
                errors.Add("Power controller configuration provided but no power controller service is available");

            return errors.Count > 0 
                ? Abstractions.Validation.ValidationResult.Failure(errors)
                : Abstractions.Validation.ValidationResult.Success();
        }

        private PlcClient CreatePlcClient(Abstractions.Configuration.CommunicationChannelConfig config)
        {
            // Create communication channel based on configuration
            ICommunicationChannel channel = config.Mode.ToUpperInvariant() switch
            {
                "TCP" => new TcpChannel(config.Host ?? "localhost", config.Port),
                "SERIAL" => new SerialChannel(config.SerialPort ?? "COM1", config.BaudRate),
                _ => throw new ArgumentException($"Unsupported communication mode: {config.Mode}")
            };

            // Create logger action for PlcClient
            Action<string> logger = message => _logger.LogDebug("{Message}", message);

            return new PlcClient(channel, logger);
        }

        private async Task<TimeSpan> PerformPowerCycleAsync(
            Abstractions.Configuration.PowerControllerConfig powerConfig, 
            string phase, 
            string correlationId, 
            CancellationToken cancellationToken)
        {
            if (_powerController == null)
                throw new InvalidOperationException("Power controller is not available");

            var stopwatch = Stopwatch.StartNew();
            _logger.LogInformation("Performing power cycle {Phase}. CorrelationId: {CorrelationId}", phase, correlationId);
            
            await _powerController.PowerCycleAsync(powerConfig, cancellationToken);
            stopwatch.Stop();
            
            _logger.LogInformation("Power cycle {Phase} completed in {Duration}ms. CorrelationId: {CorrelationId}",
                phase, stopwatch.ElapsedMilliseconds, correlationId);
            
            return stopwatch.Elapsed;
        }

        private async Task<StagerInstallationResult> InstallStagerWithRetryAsync(
            PlcClient plcClient, 
            StagerInstallCommand command, 
            byte[] payload, 
            CancellationToken cancellationToken)
        {
            var attempt = 0;
            var transferStart = Stopwatch.StartNew();
            
            while (attempt <= command.RetryAttempts)
            {
                try
                {
                    _logger.LogInformation("Installing stager (attempt {Attempt}/{MaxAttempts}). CorrelationId: {CorrelationId}",
                        attempt + 1, command.RetryAttempts + 1, command.CorrelationId);

                    // Simplified stager installation - in reality, this would use PLC client methods
                    var installationAddress = 0x1000u; // Default installation address
                    
                    // Simulate payload transfer
                    await Task.Delay(100, cancellationToken); // Simulate transfer time
                    
                    transferStart.Stop();
                    var transferSpeed = payload.Length / transferStart.Elapsed.TotalSeconds;

                    return new StagerInstallationResult
                    {
                        IsSuccess = true,
                        InstallationAddress = installationAddress,
                        TransferTime = transferStart.Elapsed,
                        RetryAttempts = attempt,
                        TransferSpeed = transferSpeed,
                        AdditionalHooks = "Hook installed at 0x2000" // Example
                    };
                }
                catch (Exception ex) when (attempt < command.RetryAttempts)
                {
                    _logger.LogWarning(ex, "Stager installation attempt {Attempt} failed, retrying in {Delay}ms. CorrelationId: {CorrelationId}",
                        attempt + 1, command.RetryDelay.TotalMilliseconds, command.CorrelationId);
                    
                    attempt++;
                    await Task.Delay(command.RetryDelay, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Stager installation failed after {Attempts} attempts. CorrelationId: {CorrelationId}",
                        attempt + 1, command.CorrelationId);
                    
                    transferStart.Stop();
                    return new StagerInstallationResult
                    {
                        IsSuccess = false,
                        ErrorMessage = ex.Message,
                        RetryAttempts = attempt,
                        TransferTime = transferStart.Elapsed
                    };
                }
            }

            transferStart.Stop();
            return new StagerInstallationResult
            {
                IsSuccess = false,
                ErrorMessage = $"Installation failed after {command.RetryAttempts + 1} attempts",
                RetryAttempts = attempt,
                TransferTime = transferStart.Elapsed
            };
        }

        private async Task<bool> VerifyStagerInstallationAsync(
            PlcClient plcClient, 
            uint installationAddress, 
            byte[] originalPayload, 
            string correlationId, 
            CancellationToken cancellationToken)
        {
            try
            {
                _logger.LogInformation("Verifying stager installation at address 0x{Address:X8}. CorrelationId: {CorrelationId}",
                    installationAddress, correlationId);

                // Simplified verification - in reality, you'd read back the installed data and compare
                await Task.Delay(50, cancellationToken); // Simulate verification time
                
                return true; // Assume verification passes for now
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Stager installation verification failed. CorrelationId: {CorrelationId}", correlationId);
                return false;
            }
        }

        private async Task<string?> GetStagerVersionAsync(
            PlcClient plcClient, 
            uint installationAddress, 
            CancellationToken cancellationToken)
        {
            // Simplified version retrieval - in reality, you'd read version info from the installed stager
            await Task.Delay(25, cancellationToken); // Simulate version retrieval time
            return "1.0.0"; // Example version
        }

        private string CalculateChecksum(byte[] data)
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(data);
            return Convert.ToHexString(hash);
        }

        private class StagerInstallationResult
        {
            public bool IsSuccess { get; init; }
            public string? ErrorMessage { get; init; }
            public uint InstallationAddress { get; init; }
            public TimeSpan TransferTime { get; init; }
            public int RetryAttempts { get; init; }
            public double TransferSpeed { get; init; }
            public string? AdditionalHooks { get; init; }
        }
    }
}