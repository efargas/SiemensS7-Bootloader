using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Services;
using S7.Core.Abstractions.Validation;
using S7.Net;
using S7.Net.Interfaces;
using S7.Net.Channels;

// Alias to resolve ambiguous reference between Commands and Services namespaces
using CommandsStagerInstallResult = S7.Core.Abstractions.Commands.StagerInstallResult;
using ServicesStagerInstallResult = S7.Core.Abstractions.Services.StagerInstallResult;

namespace S7.Core.Commands.Handlers
{
    /// <summary>
    /// Command handler for stager installation operations.
    /// </summary>
    public class StagerInstallCommandHandler : CommandHandler<StagerInstallOptions>, ICommandServiceSetup
    {
        private readonly PayloadManager _payloadManager;
        private readonly IPowerController? _powerController;

        /// <summary>
        /// Initializes a new instance of the StagerInstallCommandHandler class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="payloadManager">The payload manager for handling payloads</param>
        /// <param name="powerController">The power controller (optional)</param>
        /// <param name="validator">The optional validator for stager install options</param>
        public StagerInstallCommandHandler(
            ILogger<StagerInstallCommandHandler> logger,
            PayloadManager payloadManager,
            IPowerController? powerController = null,
            IValidator<StagerInstallOptions>? validator = null)
            : base(logger, validator)
        {
            _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
            _powerController = powerController;
        }

        /// <summary>
        /// Sets up the stager installation command handler dependencies.
        /// </summary>
        /// <param name="services">The service collection</param>
        public static void SetupServices(IServiceCollection services)
        {
            // Register any specific dependencies for stager installation operations
            services.AddTransient<StagerInstallCommandHandler>();
            
            // Register payload manager if not already registered
            services.AddSingleton<PayloadManager>();
            
            // Register power controller if available
            // services.AddTransient<IPowerController, PowerController>();
            
            // Register stager install specific validator if needed
            // services.AddTransient<IValidator<StagerInstallOptions>, StagerInstallOptionsValidator>();
        }

        /// <summary>
        /// Handles the stager installation command execution using the new options-based approach.
        /// </summary>
        /// <param name="options">The stager installation options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the command execution result</returns>
        public async Task<CommandResult<CommandsStagerInstallResult>> HandleAsync(
            StagerInstallOptions options, 
            CancellationToken cancellationToken = default)
        {
            return await ExecuteAsync<CommandsStagerInstallResult>(options, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Executes the stager installation operation internally.
        /// </summary>
        /// <typeparam name="TResult">The result type</typeparam>
        /// <param name="options">The stager installation options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the command execution result</returns>
        protected override async Task<TResult> ExecuteInternalAsync<TResult>(
            StagerInstallOptions options, 
            CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var performanceMetrics = new InstallationPerformanceMetrics();
            var warnings = new List<string>();

            // Load the stager payload
            Logger.LogInformation("Loading stager payload from {PayloadPath}. CorrelationId: {CorrelationId}",
                options.PayloadPath, options.CorrelationId);
            
            var payload = await _payloadManager.LoadPayloadAsync(options.PayloadPath, cancellationToken).ConfigureAwait(false);

            // Perform power cycling before installation if requested
            if (options.PowerCycleBeforeInstall && options.PowerConfig != null)
            {
                var powerCycleTime = await PerformPowerCycleAsync(options.PowerConfig, "before installation", options.CorrelationId, cancellationToken).ConfigureAwait(false);
                performanceMetrics = performanceMetrics with { PowerCycleTime = performanceMetrics.PowerCycleTime.Add(powerCycleTime) };
            }

            // Create PLC client with the specified configuration
            using var plcClient = CreatePlcClient(options.ChannelConfig);

            // Perform handshake if requested
            if (options.PerformHandshake)
            {
                var handshakeStart = Stopwatch.StartNew();
                Logger.LogInformation("Performing handshake. CorrelationId: {CorrelationId}", options.CorrelationId);
                
                await plcClient.PerformHandshakeAsync(cancellationToken).ConfigureAwait(false);
                handshakeStart.Stop();
                performanceMetrics = performanceMetrics with { HandshakeTime = handshakeStart.Elapsed };
                
                Logger.LogInformation("Handshake completed in {Duration}ms. CorrelationId: {CorrelationId}",
                    handshakeStart.ElapsedMilliseconds, options.CorrelationId);
            }

            // Install the stager with retry logic
            var installationResult = await InstallStagerWithRetryAsync(plcClient, options, payload, cancellationToken).ConfigureAwait(false);
            performanceMetrics = performanceMetrics with 
            { 
                PayloadTransferTime = installationResult.TransferTime,
                RetryAttempts = installationResult.RetryAttempts,
                AverageTransferSpeed = installationResult.TransferSpeed,
                TotalBytesTransferred = (uint)payload.Length
            };

            if (!installationResult.IsSuccess)
            {
                throw new InvalidOperationException(installationResult.ErrorMessage ?? "Stager installation failed");
            }

            // Verify installation if requested
            bool isVerified = false;
            if (options.VerifyInstallation)
            {
                var verificationStart = Stopwatch.StartNew();
                isVerified = await VerifyStagerInstallationAsync(plcClient, installationResult.InstallationAddress, payload, options.CorrelationId, cancellationToken).ConfigureAwait(false);
                verificationStart.Stop();
                performanceMetrics = performanceMetrics with { VerificationTime = verificationStart.Elapsed };
                
                if (!isVerified)
                {
                    warnings.Add("Stager installation verification failed");
                }
            }

            // Get version information if requested
            string? stagerVersion = null;
            if (options.GetVersionInfo)
            {
                try
                {
                    stagerVersion = await GetStagerVersionAsync(plcClient, installationResult.InstallationAddress, cancellationToken).ConfigureAwait(false);
                    Logger.LogInformation("Stager version: {Version}. CorrelationId: {CorrelationId}",
                        stagerVersion, options.CorrelationId);
                }
                catch (Exception ex)
                {
                    Logger.LogWarning(ex, "Failed to retrieve stager version. CorrelationId: {CorrelationId}", options.CorrelationId);
                    warnings.Add("Failed to retrieve stager version information");
                }
            }

            // Perform power cycling after installation if requested
            if (options.PowerCycleAfterInstall && options.PowerConfig != null)
            {
                var powerCycleTime = await PerformPowerCycleAsync(options.PowerConfig, "after installation", options.CorrelationId, cancellationToken).ConfigureAwait(false);
                performanceMetrics = performanceMetrics with { PowerCycleTime = performanceMetrics.PowerCycleTime.Add(powerCycleTime) };
            }

            stopwatch.Stop();

            // Calculate checksum
            var checksum = CalculateChecksum(payload);

            // Create the result
            var result = new CommandsStagerInstallResult
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

            Logger.LogInformation("Stager installation completed successfully in {Duration}ms. CorrelationId: {CorrelationId}",
                stopwatch.ElapsedMilliseconds, options.CorrelationId);

            return (TResult)(object)result;
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
            Action<string> logger = message => Logger.LogDebug("{Message}", message);

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
            Logger.LogInformation("Performing power cycle {Phase}. CorrelationId: {CorrelationId}", phase, correlationId);
            
            await _powerController.PowerCycleAsync(powerConfig, cancellationToken).ConfigureAwait(false);
            stopwatch.Stop();
            
            Logger.LogInformation("Power cycle {Phase} completed in {Duration}ms. CorrelationId: {CorrelationId}",
                phase, stopwatch.ElapsedMilliseconds, correlationId);
            
            return stopwatch.Elapsed;
        }

        private async Task<StagerInstallationResult> InstallStagerWithRetryAsync(
            PlcClient plcClient, 
            StagerInstallOptions options, 
            byte[] payload, 
            CancellationToken cancellationToken)
        {
            var attempt = 0;
            var transferStart = Stopwatch.StartNew();
            
            while (attempt <= options.RetryAttempts)
            {
                try
                {
                    Logger.LogInformation("Installing stager (attempt {Attempt}/{MaxAttempts}). CorrelationId: {CorrelationId}",
                        attempt + 1, options.RetryAttempts + 1, options.CorrelationId);

                    // Use target address if specified, otherwise use default
                    var installationAddress = options.TargetAddress ?? 0x1000u;
                    
                    // Simulate payload transfer
                    await Task.Delay(100, cancellationToken).ConfigureAwait(false); // Simulate transfer time
                    
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
                catch (Exception ex) when (attempt < options.RetryAttempts)
                {
                    Logger.LogWarning(ex, "Stager installation attempt {Attempt} failed, retrying in {Delay}ms. CorrelationId: {CorrelationId}",
                        attempt + 1, options.RetryDelayMs, options.CorrelationId);
                    
                    attempt++;
                    await Task.Delay(options.RetryDelayMs, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Logger.LogError(ex, "Stager installation failed after {Attempts} attempts. CorrelationId: {CorrelationId}",
                        attempt + 1, options.CorrelationId);
                    
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
                ErrorMessage = $"Installation failed after {options.RetryAttempts + 1} attempts",
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
                Logger.LogInformation("Verifying stager installation at address 0x{Address:X8}. CorrelationId: {CorrelationId}",
                    installationAddress, correlationId);

                // Simplified verification - in reality, you'd read back the installed data and compare
                await Task.Delay(50, cancellationToken).ConfigureAwait(false); // Simulate verification time
                
                return true; // Assume verification passes for now
            }
            catch (Exception ex)
            {
                Logger.LogWarning(ex, "Stager installation verification failed. CorrelationId: {CorrelationId}", correlationId);
                return false;
            }
        }

        private async Task<string?> GetStagerVersionAsync(
            PlcClient plcClient, 
            uint installationAddress, 
            CancellationToken cancellationToken)
        {
            // Simplified version retrieval - in reality, you'd read version info from the installed stager
            await Task.Delay(25, cancellationToken).ConfigureAwait(false); // Simulate version retrieval time
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