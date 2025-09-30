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
    /// Command handler for memory dump operations.
    /// </summary>
    public class MemoryDumpCommandHandler : CommandHandler<MemoryDumpOptions>
    {
        private readonly PayloadManager _payloadManager;
        private readonly ICommunicationChannelFactory _channelFactory;
        private readonly IPlcClientFactory _plcClientFactory;
        private readonly IPlcMemoryAccessor? _testPlcClient; // Use the most specific interface needed for testing
        private readonly ICommunicationChannel? _testChannel;

        /// <summary>
        /// Initializes a new instance of the <see cref="MemoryDumpCommandHandler"/> class.
        /// </summary>
        public MemoryDumpCommandHandler(
            ILogger<MemoryDumpCommandHandler> logger,
            PayloadManager payloadManager,
            ICommunicationChannelFactory channelFactory,
            IPlcClientFactory plcClientFactory)
            : base(logger)
        {
            _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
            _channelFactory = channelFactory ?? throw new ArgumentNullException(nameof(channelFactory));
            _plcClientFactory = plcClientFactory ?? throw new ArgumentNullException(nameof(plcClientFactory));
        }

        /// <summary>
        /// Internal constructor for testing purposes.
        /// </summary>
        internal MemoryDumpCommandHandler(
            ILogger<MemoryDumpCommandHandler> logger,
            PayloadManager payloadManager,
            ICommunicationChannel testChannel,
            IPlcMemoryAccessor testPlcClient) // Depend on the interface
            : base(logger)
        {
            _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
            _testChannel = testChannel;
            _testPlcClient = testPlcClient;
            _channelFactory = null!; // Not used when a test channel is provided
            _plcClientFactory = null!; // Not used when a test client is provided
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

            // ... (rest of validation is unchanged)

            return errors.Count > 0 ? ValidationResult.Failure(errors) : ValidationResult.Success();
        }

        /// <summary>
        /// Executes the memory dump command.
        /// </summary>
        public override async Task<CommandResult> ExecuteAsync(MemoryDumpOptions options, CancellationToken cancellationToken)
        {
            var channel = _testChannel ?? _channelFactory.Create(options.ChannelConfig);
            // The factory now handles client creation and its dependencies.
            var plcClient = _testPlcClient ?? _plcClientFactory.Create(channel);

            try
            {
                LogProgress("Connecting to PLC", options.CorrelationId);
                await channel.ConnectAsync().ConfigureAwait(false);

                if (!channel.IsConnected)
                {
                    return CommandResult.Failure("Failed to establish connection to PLC");
                }

                LogProgress("Connection established successfully", options.CorrelationId);

                LogProgress("Loading memory dumper payload", options.CorrelationId);
                var dumperPayload = await _payloadManager.GetMemoryDumperPayloadAsync().ConfigureAwait(false);
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
                // Dispose the concrete client if we created it. The test client's lifecycle is managed by the test.
                if (plcClient is IDisposable disposableClient && plcClient != _testPlcClient)
                {
                    disposableClient.Dispose();
                }
                if (channel != _testChannel)
                {
                    channel.Dispose();
                }
            }
        }

        /// <summary>
        /// Generates the output filename for the memory dump.
        /// </summary>
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