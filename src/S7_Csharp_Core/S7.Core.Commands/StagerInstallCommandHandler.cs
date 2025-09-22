using Microsoft.Extensions.Logging;
using S7.Net;
using S7.Net.Channels;
using S7.Net.Interfaces;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Commands
{
    /// <summary>
    /// Command handler for stager installation operations.
    /// </summary>
    public class StagerInstallCommandHandler : CommandHandler<StagerInstallOptions>
    {
        private readonly PayloadManager _payloadManager;
        private readonly IPowerController _powerController;

        /// <summary>
        /// Initializes a new instance of the StagerInstallCommandHandler class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="payloadManager">The payload manager for loading stager payload</param>
        /// <param name="powerController">The power controller for power cycling operations</param>
        public StagerInstallCommandHandler(
            ILogger<StagerInstallCommandHandler> logger, 
            PayloadManager payloadManager,
            IPowerController powerController)
            : base(logger)
        {
            _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
            _powerController = powerController ?? throw new ArgumentNullException(nameof(powerController));
        }

        /// <summary>
        /// Validates the stager installation options.
        /// </summary>
        /// <param name="options">The options to validate</param>
        /// <returns>A validation result</returns>
        protected override ValidationResult ValidateOptions(StagerInstallOptions options)
        {
            var baseValidation = base.ValidateOptions(options);
            if (!baseValidation.IsValid)
                return baseValidation;

            var errors = new System.Collections.Generic.List<string>();

            // Validate payload path exists
            if (!Directory.Exists(options.PayloadPath))
            {
                errors.Add($"Payload directory does not exist: {options.PayloadPath}");
            }

            // Validate communication channel configuration
            if (options.ChannelConfig.Mode.Equals("TCP", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(options.ChannelConfig.Host))
                {
                    errors.Add("TCP host is required when using TCP communication mode");
                }
            }
            else if (options.ChannelConfig.Mode.Equals("Serial", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(options.ChannelConfig.SerialPort))
                {
                    errors.Add("Serial port is required when using Serial communication mode");
                }
            }
            else
            {
                errors.Add($"Unsupported communication mode: {options.ChannelConfig.Mode}");
            }

            // Validate power configuration
            if (string.IsNullOrWhiteSpace(options.PowerConfig.Host))
            {
                errors.Add("Power controller host is required");
            }

            return errors.Count > 0 ? ValidationResult.Failure(errors) : ValidationResult.Success();
        }

        /// <summary>
        /// Executes the stager installation command.
        /// </summary>
        /// <param name="options">The command options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>A command result with installation details</returns>
        protected override async Task<CommandResult> ExecuteAsync(StagerInstallOptions options, CancellationToken cancellationToken)
        {
            ICommunicationChannel? channel = null;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                LogProgress("Starting stager installation sequence", options.CorrelationId);

                // Step 1: Power cycle the PLC
                LogProgress("Performing power cycle", options.CorrelationId);
                await _powerController.PowerCycleAsync(
                    options.PowerConfig.Host,
                    options.PowerConfig.Port,
                    options.PowerConfig.Coil,
                    options.PowerConfig.DelaySeconds,
                    cancellationToken).ConfigureAwait(false);

                // Small delay after power cycle
                await Task.Delay(50, cancellationToken).ConfigureAwait(false);

                // Step 2: Create and connect communication channel
                LogProgress("Creating communication channel", options.CorrelationId);
                channel = CreateCommunicationChannel(options.ChannelConfig);

                LogProgress($"Connecting to PLC at {options.ChannelConfig.Host}:{options.ChannelConfig.Port}", options.CorrelationId);
                await channel.ConnectAsync().ConfigureAwait(false);

                if (!channel.IsConnected)
                {
                    return CommandResult.Failure("Failed to establish connection to PLC after power cycle");
                }

                LogProgress("Connection established successfully", options.CorrelationId);

                // Step 3: Create PLC client and perform handshake
                var plcClient = new PlcClient(channel, message => 
                    Logger.LogInformation("PLC: {Message} [CorrelationId: {CorrelationId}]", message, options.CorrelationId));

                if (options.PerformHandshake)
                {
                    LogProgress("Performing handshake", options.CorrelationId);
                    var handshakeSuccess = await plcClient.PerformHandshakeAsync().ConfigureAwait(false);
                    
                    if (!handshakeSuccess)
                    {
                        return CommandResult.Failure("Handshake with PLC failed");
                    }

                    LogProgress("Handshake completed successfully", options.CorrelationId);
                }

                // Step 4: Get version information if requested
                string? versionInfo = null;
                if (options.GetVersionInfo)
                {
                    LogProgress("Getting PLC version information", options.CorrelationId);
                    versionInfo = await plcClient.GetVersion().ConfigureAwait(false);
                    Logger.LogInformation("PLC Version: {Version} [CorrelationId: {CorrelationId}]", versionInfo, options.CorrelationId);
                }

                // Step 5: Load and install stager payload
                LogProgress("Loading stager payload", options.CorrelationId);
                var stagerPayload = await _payloadManager.GetStagerPayloadAsync(options.PayloadPath).ConfigureAwait(false);
                Logger.LogDebug("Loaded stager payload: {PayloadSize} bytes [CorrelationId: {CorrelationId}]", 
                    stagerPayload.Length, options.CorrelationId);

                LogProgress("Installing stager payload", options.CorrelationId);
                await plcClient.InstallStager(stagerPayload).ConfigureAwait(false);

                stopwatch.Stop();

                LogProgress("Stager installation completed successfully", options.CorrelationId);

                Logger.LogInformation("Stager installation completed in {Duration:F1}s [CorrelationId: {CorrelationId}]",
                    stopwatch.Elapsed.TotalSeconds, options.CorrelationId);

                return CommandResult.Success(new StagerInstallResult
                {
                    IsInstalled = true,
                    PayloadSize = (uint)stagerPayload.Length,
                    DurationSeconds = stopwatch.Elapsed.TotalSeconds,
                    VersionInfo = versionInfo,
                    HandshakePerformed = options.PerformHandshake
                });
            }
            catch (TimeoutException ex)
            {
                Logger.LogError(ex, "Timeout during stager installation [CorrelationId: {CorrelationId}]", options.CorrelationId);
                return CommandResult.Failure($"Operation timed out: {ex.Message}");
            }
            catch (IOException ex)
            {
                Logger.LogError(ex, "I/O error during stager installation [CorrelationId: {CorrelationId}]", options.CorrelationId);
                return CommandResult.Failure($"Communication error: {ex.Message}");
            }
            catch (Exception ex) when (!(ex is OperationCanceledException))
            {
                Logger.LogError(ex, "Stager installation failed [CorrelationId: {CorrelationId}]", options.CorrelationId);
                return CommandResult.FromException(ex);
            }
            finally
            {
                if (channel != null)
                {
                    LogProgress("Disconnecting from PLC", options.CorrelationId);
                    channel.Disconnect();
                }
            }
        }

        /// <summary>
        /// Creates a communication channel based on the configuration.
        /// </summary>
        /// <param name="config">The channel configuration</param>
        /// <returns>A communication channel instance</returns>
        private static ICommunicationChannel CreateCommunicationChannel(CommunicationChannelConfig config)
        {
            return config.Mode.ToUpperInvariant() switch
            {
                "TCP" => new TcpChannel(config.Host ?? "localhost", config.Port),
                "SERIAL" => new SerialChannel(
                    config.SerialPort ?? throw new ArgumentException("Serial port is required for serial communication"),
                    config.BaudRate,
                    config.Parity,
                    config.StopBits,
                    config.FlowControl),
                _ => throw new ArgumentException($"Unsupported communication mode: {config.Mode}")
            };
        }
    }

    /// <summary>
    /// Interface for power controller operations.
    /// </summary>
    public interface IPowerController
    {
        /// <summary>
        /// Performs a power cycle operation.
        /// </summary>
        /// <param name="host">The Modbus host</param>
        /// <param name="port">The Modbus port</param>
        /// <param name="coil">The coil address</param>
        /// <param name="delaySeconds">The delay after power cycle</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>A task representing the operation</returns>
        Task PowerCycleAsync(string host, int port, int coil, int delaySeconds, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Result data for stager installation operations.
    /// </summary>
    public class StagerInstallResult
    {
        /// <summary>
        /// Gets or sets a value indicating whether the stager was successfully installed.
        /// </summary>
        public bool IsInstalled { get; set; }

        /// <summary>
        /// Gets or sets the size of the installed payload in bytes.
        /// </summary>
        public uint PayloadSize { get; set; }

        /// <summary>
        /// Gets or sets the duration of the installation in seconds.
        /// </summary>
        public double DurationSeconds { get; set; }

        /// <summary>
        /// Gets or sets the PLC version information if retrieved.
        /// </summary>
        public string? VersionInfo { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether a handshake was performed.
        /// </summary>
        public bool HandshakePerformed { get; set; }
    }
}