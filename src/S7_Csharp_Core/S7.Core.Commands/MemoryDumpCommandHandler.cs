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
        private readonly ILoggerFactory _loggerFactory;
        private readonly PlcClient? _plcClient;

        /// <summary>
        /// Initializes a new instance of the MemoryDumpCommandHandler class.
        /// </summary>
        public MemoryDumpCommandHandler(ILogger<MemoryDumpCommandHandler> logger, PayloadManager payloadManager, ILoggerFactory loggerFactory)
            : base(logger)
        {
            _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
            _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        }

        private readonly ICommunicationChannel? _testChannel;

        internal MemoryDumpCommandHandler(ILogger<MemoryDumpCommandHandler> logger, PayloadManager payloadManager, ICommunicationChannel testChannel, ILoggerFactory loggerFactory)
            : base(logger)
        {
            _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
            _testChannel = testChannel;
            _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        }

        /// <summary>
        /// Validates the memory dump options.
        /// </summary>
        protected override ValidationResult ValidateOptions(MemoryDumpOptions options)
        {
            var baseValidation = base.ValidateOptions(options);
            if (!baseValidation.IsValid)
                return baseValidation;

            var errors = new System.Collections.Generic.List<string>();

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
        public override async Task<CommandResult> ExecuteAsync(MemoryDumpOptions options, CancellationToken cancellationToken)
        {
            ICommunicationChannel? channel = null;
            try
            {
                LogProgress("Creating communication channel", options.CorrelationId);
                channel = _testChannel ?? CreateCommunicationChannel(options.ChannelConfig);

                LogProgress("Connecting to PLC", options.CorrelationId);
                await channel.ConnectAsync(cancellationToken).ConfigureAwait(false);

                if (!channel.IsConnected)
                {
                    return CommandResult.Failure("Failed to establish connection to PLC");
                }

                LogProgress("Connection established successfully", options.CorrelationId);

                var plcClient = _plcClient ?? new PlcClient(channel, _loggerFactory);

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

                var outputFilename = GenerateOutputFilename(options);
                var fullOutputPath = Path.Combine(options.OutputPath, outputFilename);
                var partialFilePath = fullOutputPath + ".partial";

                var dumpedData = await plcClient.DumpMemoryAsync(options.Address, options.Length, dumperPayload, progress, cancellationToken).ConfigureAwait(false);
                stopwatch.Stop();

                LogProgress("Memory dump completed, saving to file", options.CorrelationId);

                await File.WriteAllBytesAsync(partialFilePath, dumpedData, cancellationToken).ConfigureAwait(false);
                File.Move(partialFilePath, fullOutputPath, true);


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
                channel?.Dispose();
            }
        }

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
        public string OutputFilePath { get; set; } = string.Empty;
        public uint BytesDumped { get; set; }
        public double DurationSeconds { get; set; }
        public uint Address { get; set; }
        public uint Length { get; set; }
    }
}