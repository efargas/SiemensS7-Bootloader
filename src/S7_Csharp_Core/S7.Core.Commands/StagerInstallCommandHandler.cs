using Microsoft.Extensions.Logging;
using S7.Net;
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
        private readonly ICommunicationChannelFactory _channelFactory;
        private readonly ILogger<PlcClient> _plcClientLogger;
        private readonly ILogger<PlcProtocol> _plcProtocolLogger;

        /// <summary>
        /// Initializes a new instance of the <see cref="StagerInstallCommandHandler"/> class.
        /// </summary>
        /// <param name="logger">The logger for this command handler.</param>
        /// <param name="payloadManager">The payload manager for loading stager payloads.</param>
        /// <param name="powerController">The power controller for power cycling operations.</param>
        /// <param name="channelFactory">The factory for creating communication channels.</param>
        /// <param name="plcClientLogger">The logger for the PLC client.</param>
        /// <param name="plcProtocolLogger">The logger for the PLC protocol.</param>
        public StagerInstallCommandHandler(
            ILogger<StagerInstallCommandHandler> logger,
            PayloadManager payloadManager,
            IPowerController powerController,
            ICommunicationChannelFactory channelFactory,
            ILogger<PlcClient> plcClientLogger,
            ILogger<PlcProtocol> plcProtocolLogger)
            : base(logger)
        {
            _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
            _powerController = powerController ?? throw new ArgumentNullException(nameof(powerController));
            _channelFactory = channelFactory ?? throw new ArgumentNullException(nameof(channelFactory));
            _plcClientLogger = plcClientLogger ?? throw new ArgumentNullException(nameof(plcClientLogger));
            _plcProtocolLogger = plcProtocolLogger ?? throw new ArgumentNullException(nameof(plcProtocolLogger));
        }

        /// <summary>
        /// Validates the stager installation options.
        /// </summary>
        /// <param name="options">The options to validate.</param>
        /// <returns>A validation result.</returns>
        protected override ValidationResult ValidateOptions(StagerInstallOptions options)
        {
            var baseValidation = base.ValidateOptions(options);
            if (!baseValidation.IsValid)
                return baseValidation;

            var errors = new System.Collections.Generic.List<string>();

            if (!Directory.Exists(options.PayloadPath))
            {
                errors.Add($"Payload directory does not exist: {options.PayloadPath}");
            }

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

            if (string.IsNullOrWhiteSpace(options.PowerConfig.Host))
            {
                errors.Add("Power controller host is required");
            }

            return errors.Count > 0 ? ValidationResult.Failure(errors) : ValidationResult.Success();
        }

        /// <summary>
        /// Executes the stager installation command.
        /// </summary>
        /// <param name="options">The command options.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A command result with installation details.</returns>
        protected override async Task<CommandResult> ExecuteAsync(StagerInstallOptions options, CancellationToken cancellationToken)
        {
            ICommunicationChannel? channel = null;
            PlcClient? plcClient = null;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                LogProgress("Starting stager installation sequence", options.CorrelationId);

                LogProgress("Performing power cycle", options.CorrelationId);
                await _powerController.PowerCycleAsync(
                    options.PowerConfig.Host,
                    options.PowerConfig.Port,
                    options.PowerConfig.Coil,
                    options.PowerConfig.DelaySeconds,
                    cancellationToken).ConfigureAwait(false);

                await Task.Delay(50, cancellationToken).ConfigureAwait(false);

                LogProgress("Creating communication channel", options.CorrelationId);
                channel = _channelFactory.Create(options.ChannelConfig);

                LogProgress($"Connecting to PLC at {options.ChannelConfig.Host}:{options.ChannelConfig.Port}", options.CorrelationId);
                await channel.ConnectAsync().ConfigureAwait(false);

                if (!channel.IsConnected)
                {
                    return CommandResult.Failure("Failed to establish connection to PLC after power cycle");
                }

                LogProgress("Connection established successfully", options.CorrelationId);

                plcClient = new PlcClient(channel, _plcClientLogger, _plcProtocolLogger);

                if (options.PerformHandshake)
                {
                    LogProgress("Performing handshake", options.CorrelationId);
                    var handshakeSuccess = await plcClient.PerformHandshakeAsync(cancellationToken).ConfigureAwait(false);
                    
                    if (!handshakeSuccess)
                    {
                        return CommandResult.Failure("Handshake with PLC failed");
                    }

                    LogProgress("Handshake completed successfully", options.CorrelationId);
                }

                string? versionInfo = null;
                if (options.GetVersionInfo)
                {
                    LogProgress("Getting PLC version information", options.CorrelationId);
                    versionInfo = await plcClient.GetVersion(cancellationToken).ConfigureAwait(false);
                    Logger.LogInformation("PLC Version: {Version} [CorrelationId: {CorrelationId}]", versionInfo, options.CorrelationId);
                }

                LogProgress("Loading stager payload", options.CorrelationId);
                var stagerPayload = await _payloadManager.GetStagerPayloadAsync().ConfigureAwait(false);
                Logger.LogDebug("Loaded stager payload: {PayloadSize} bytes [CorrelationId: {CorrelationId}]", 
                    stagerPayload.Length, options.CorrelationId);

                LogProgress("Installing stager payload", options.CorrelationId);
                await plcClient.InstallStager(stagerPayload, cancellationToken).ConfigureAwait(false);

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
            catch (Exception ex) when (ex is TimeoutException || ex is IOException || ex is S7.Net.Exceptions.PlcCommunicationException)
            {
                Logger.LogError(ex, "A communication error occurred during stager installation [CorrelationId: {CorrelationId}]", options.CorrelationId);
                return CommandResult.Failure($"Communication error: {ex.Message}");
            }
            catch (Exception ex) when (!(ex is OperationCanceledException))
            {
                Logger.LogError(ex, "Stager installation failed with an unexpected error [CorrelationId: {CorrelationId}]", options.CorrelationId);
                return CommandResult.FromException(ex);
            }
            finally
            {
                plcClient?.Dispose();
                channel?.Dispose();
            }
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
        Task PowerCycleAsync(string host, int port, int coil, int delaySeconds, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Result data for stager installation operations.
    /// </summary>
    public class StagerInstallResult
    {
        public bool IsInstalled { get; set; }
        public uint PayloadSize { get; set; }
        public double DurationSeconds { get; set; }
        public string? VersionInfo { get; set; }
        public bool HandshakePerformed { get; set; }
    }
}