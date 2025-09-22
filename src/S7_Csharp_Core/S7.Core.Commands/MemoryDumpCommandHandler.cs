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
    /// Command handler for memory dump operations.
    /// </summary>
    public class MemoryDumpCommandHandler : CommandHandler<MemoryDumpOptions>
    {
        private readonly PayloadManager _payloadManager;

        /// <summary>
        /// Initializes a new instance of the MemoryDumpCommandHandler class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="payloadManager">The payload manager for loading dumper payload</param>
        public MemoryDumpCommandHandler(ILogger<MemoryDumpCommandHandler> logger, PayloadManager payloadManager)
            : base(logger)
        {
            _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
        }

        /// <summary>
        /// Validates the memory dump options.
        /// </summary>
        /// <param name="options">The options to validate</param>
        /// <returns>A validation result</returns>
        protected override ValidationResult ValidateOptions(MemoryDumpOptions options)
        {
            var baseValidation = base.ValidateOptions(options);
            if (!baseValidation.IsValid)
                return baseValidation;

            var errors = new System.Collections.Generic.List<string>();

            // Validate output directory exists or can be created
            try
            {
                var outputDir = Path.GetDirectoryName(options.OutputPath);
                if (!string.IsNullOrEmpty(outputDir) && !Directory.Exists(outputDir))
                {
                    Directory.CreateDirectory(outputDir);
                }
            }
            catch (Exception ex)
            {
                errors.Add($"Cannot create output directory: {ex.Message}");
            }

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

            // Check if output file already exists and overwrite is not allowed
            var outputFilename = GenerateOutputFilename(options);
            var fullOutputPath = Path.Combine(options.OutputPath, outputFilename);
            if (File.Exists(fullOutputPath) && !options.OverwriteExisting)
            {
                errors.Add($"Output file already exists and overwrite is not allowed: {fullOutputPath}");
            }

            return errors.Count > 0 ? ValidationResult.Failure(errors) : ValidationResult.Success();
        }

        /// <summary>
        /// Executes the memory dump command.
        /// </summary>
        /// <param name="options">The command options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>A command result with the output file path</returns>
        protected override async Task<CommandResult> ExecuteAsync(MemoryDumpOptions options, CancellationToken cancellationToken)
        {
            ICommunicationChannel? channel = null;
            try
            {
                LogProgress("Creating communication channel", options.CorrelationId);
                channel = CreateCommunicationChannel(options.ChannelConfig);

                LogProgress("Connecting to PLC", options.CorrelationId);
                await channel.ConnectAsync().ConfigureAwait(false);

                if (!channel.IsConnected)
                {
                    return CommandResult.Failure("Failed to establish connection to PLC");
                }

                LogProgress("Connection established successfully", options.CorrelationId);

                var plcClient = new PlcClient(channel, message => 
                    Logger.LogInformation("PLC: {Message} [CorrelationId: {CorrelationId}]", message, options.CorrelationId));

                LogProgress("Loading memory dumper payload", options.CorrelationId);
                var dumperPayload = await _payloadManager.GetMemoryDumperPayloadAsync(options.PayloadPath).ConfigureAwait(false);
                Logger.LogDebug("Loaded dumper payload: {PayloadSize} bytes [CorrelationId: {CorrelationId}]", 
                    dumperPayload.Length, options.CorrelationId);

                LogProgress($"Starting memory dump: {options.Length} bytes from 0x{options.Address:X8}", options.CorrelationId);

                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                var progress = new Progress<long>(bytesRead =>
                {
                    var percentage = (double)bytesRead / options.Length * 100;
                    var elapsed = stopwatch.Elapsed;
                    var bytesPerSecond = bytesRead > 0 ? bytesRead / elapsed.TotalSeconds : 0;
                    var remainingSeconds = bytesPerSecond > 0 ? (options.Length - bytesRead) / bytesPerSecond : 0;

                    Logger.LogInformation("Memory dump progress: {BytesRead}/{TotalBytes} bytes ({Percentage:F1}%) - " +
                        "Elapsed: {Elapsed:F0}s, Remaining: {Remaining:F0}s [CorrelationId: {CorrelationId}]",
                        bytesRead, options.Length, percentage, elapsed.TotalSeconds, remainingSeconds, options.CorrelationId);
                });

                var dumpedData = await plcClient.DumpMemoryAsync(options.Address, options.Length, dumperPayload, progress).ConfigureAwait(false);
                stopwatch.Stop();

                LogProgress("Memory dump completed, saving to file", options.CorrelationId);

                var outputFilename = GenerateOutputFilename(options);
                var fullOutputPath = Path.Combine(options.OutputPath, outputFilename);

                await File.WriteAllBytesAsync(fullOutputPath, dumpedData, cancellationToken).ConfigureAwait(false);

                Logger.LogInformation("Memory dump saved successfully: {FilePath} ({FileSize} bytes) in {Duration:F1}s [CorrelationId: {CorrelationId}]",
                    fullOutputPath, dumpedData.Length, stopwatch.Elapsed.TotalSeconds, options.CorrelationId);

                return CommandResult.Success(new MemoryDumpResult
                {
                    OutputFilePath = fullOutputPath,
                    BytesDumped = (uint)dumpedData.Length,
                    DurationSeconds = stopwatch.Elapsed.TotalSeconds,
                    Address = options.Address,
                    Length = options.Length
                });
            }
            catch (Exception ex) when (!(ex is OperationCanceledException))
            {
                Logger.LogError(ex, "Memory dump operation failed [CorrelationId: {CorrelationId}]", options.CorrelationId);
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

        /// <summary>
        /// Generates the output filename for the memory dump.
        /// </summary>
        /// <param name="options">The command options</param>
        /// <returns>The generated filename</returns>
        private static string GenerateOutputFilename(MemoryDumpOptions options)
        {
            if (!string.IsNullOrWhiteSpace(options.CustomFilename))
            {
                return options.CustomFilename.EndsWith(".bin") ? options.CustomFilename : $"{options.CustomFilename}.bin";
            }

            var endAddress = options.Address + options.Length;
            return $"mem_dump_{options.Address:x8}_{endAddress:x8}.bin";
        }
    }

    /// <summary>
    /// Result data for memory dump operations.
    /// </summary>
    public class MemoryDumpResult
    {
        /// <summary>
        /// Gets or sets the path to the output file.
        /// </summary>
        public string OutputFilePath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the number of bytes that were dumped.
        /// </summary>
        public uint BytesDumped { get; set; }

        /// <summary>
        /// Gets or sets the duration of the operation in seconds.
        /// </summary>
        public double DurationSeconds { get; set; }

        /// <summary>
        /// Gets or sets the starting address that was dumped.
        /// </summary>
        public uint Address { get; set; }

        /// <summary>
        /// Gets or sets the length that was requested to be dumped.
        /// </summary>
        public uint Length { get; set; }
    }
}