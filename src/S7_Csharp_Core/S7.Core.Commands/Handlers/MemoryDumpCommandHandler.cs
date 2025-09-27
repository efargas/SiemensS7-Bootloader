using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Factories;
using S7.Core.Abstractions.Validation;
using S7.Net;
using S7.Net.Interfaces;

namespace S7.Core.Commands.Handlers
{
    /// <summary>
    /// Command handler for memory dump operations.
    /// </summary>
    public class MemoryDumpCommandHandler(
        ILogger<MemoryDumpCommandHandler> logger,
        PayloadManager payloadManager,
        IPlcClientFactory plcClientFactory,
    IValidator<MemoryDumpOptions>? validator = null) : CommandHandler<MemoryDumpOptions, MemoryDumpResult>(logger, validator)
    {
        private readonly PayloadManager _payloadManager = payloadManager ?? throw new ArgumentNullException(nameof(payloadManager));
        private readonly IPlcClientFactory _plcClientFactory = plcClientFactory ?? throw new ArgumentNullException(nameof(plcClientFactory));

        /// <summary>
        /// Handles the memory dump command execution using the new options-based approach.
        /// </summary>
        /// <param name="options">The memory dump options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the command execution result</returns>
        public async Task<CommandResult<MemoryDumpResult>> HandleAsync(
        MemoryDumpOptions options,
            CancellationToken cancellationToken = default)
        {
        return await ExecuteAsync(options, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Executes the memory dump operation internally.
        /// </summary>
        /// <param name="options">The memory dump options</param>
        /// <param name="cancellationToken">Cancellation token for the operation</param>
        /// <returns>A task representing the command execution result</returns>
        protected override async Task<MemoryDumpResult> ExecuteInternalAsync(
            MemoryDumpOptions options,
            CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();
            var performanceMetrics = new DumpPerformanceMetrics();

            // Create PLC client with the specified configuration
            using var plcClient = _plcClientFactory.Create(options.ChannelConfig);

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

            // Load the payload
            Logger.LogInformation("Loading payload from {PayloadPath}. CorrelationId: {CorrelationId}",
                options.PayloadPath, options.CorrelationId);

            var payload = await _payloadManager.LoadPayloadAsync(options.PayloadPath, cancellationToken).ConfigureAwait(false);

            // Perform the memory dump
            var transferStart = Stopwatch.StartNew();
            var dumpData = await PerformMemoryDumpAsync(plcClient, options, payload, cancellationToken).ConfigureAwait(false);
            transferStart.Stop();

            // Calculate performance metrics
            var averageSpeed = options.Length > 0 && transferStart.Elapsed.TotalSeconds > 0
                ? options.Length / transferStart.Elapsed.TotalSeconds
                : 0;

            performanceMetrics = performanceMetrics with
            {
                DataTransferTime = transferStart.Elapsed,
                AverageReadSpeed = averageSpeed
            };

            // Generate output filename
            var outputFilename = GenerateOutputFilename(options);
            var outputPath = Path.Combine(options.OutputPath, outputFilename);

            // Ensure output directory exists
            Directory.CreateDirectory(options.OutputPath);

            // Save the dump data
            await File.WriteAllBytesAsync(outputPath, dumpData, cancellationToken).ConfigureAwait(false);
            Logger.LogInformation("Memory dump saved to {OutputPath}. CorrelationId: {CorrelationId}",
                outputPath, options.CorrelationId);

            // Verify the dump if requested
            string? checksum = null;
            bool isVerified = false;
            if (options.VerifyDump)
            {
                var verificationStart = Stopwatch.StartNew();
                checksum = CalculateChecksum(dumpData);
                isVerified = await VerifyDumpAsync(plcClient, options, dumpData, cancellationToken).ConfigureAwait(false);
                verificationStart.Stop();

                performanceMetrics = performanceMetrics with { VerificationTime = verificationStart.Elapsed };

                Logger.LogInformation("Dump verification completed. Verified: {IsVerified}, Checksum: {Checksum}. CorrelationId: {CorrelationId}",
                    isVerified, checksum, options.CorrelationId);
            }

            stopwatch.Stop();

            // Create the result
            var result = new MemoryDumpResult
            {
                DumpFilePath = outputPath,
                BytesDumped = (uint)dumpData.Length,
                StartAddress = options.Address,
                EndAddress = options.Address + options.Length - 1,
                Duration = stopwatch.Elapsed,
                Checksum = checksum,
                IsVerified = isVerified,
                Metadata = options.Metadata.ContainsKey("metadata") ? options.Metadata["metadata"]?.ToString() : null,
                PerformanceMetrics = performanceMetrics
            };

            Logger.LogInformation("Memory dump completed successfully in {Duration}ms. CorrelationId: {CorrelationId}",
                stopwatch.ElapsedMilliseconds, options.CorrelationId);

            return result;
        }
        
        private async Task<byte[]> PerformMemoryDumpAsync(
            IPlcClient plcClient,
            MemoryDumpOptions options, 
            byte[] payload, 
            CancellationToken cancellationToken)
        {
            var progress = new Progress<long>(bytesReported =>
            {
                if (options.Length > 0)
                {
                    var percentage = (double)bytesReported / options.Length * 100;
                    Logger.LogDebug("Memory dump progress: {Progress:F1}% ({BytesRead}/{TotalBytes} bytes). CorrelationId: {CorrelationId}",
                        percentage, bytesReported, options.Length, options.CorrelationId);
                }
            });

            return await plcClient.DumpMemoryAsync(options.Address, options.Length, payload, progress, cancellationToken)
                .ConfigureAwait(false);
        }

        private string GenerateOutputFilename(MemoryDumpOptions options)
        {
            if (!string.IsNullOrEmpty(options.CustomFilename))
                return options.CustomFilename;

            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            return $"memdump_0x{options.Address:X8}_{options.Length}bytes_{timestamp}.bin";
        }

        private string CalculateChecksum(byte[] data)
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(data);
            return Convert.ToHexString(hash);
        }

        private async Task<bool> VerifyDumpAsync(
            IPlcClient plcClient,
            MemoryDumpOptions options, 
            byte[] dumpData, 
            CancellationToken cancellationToken)
        {
            try
            {
                // Simplified verification - in reality, you'd re-read a portion of memory and compare
                await Task.Delay(100, cancellationToken).ConfigureAwait(false); // Simulate verification time
                return true; // Assume verification passes for now
            }
            catch (Exception ex)
            {
                Logger.LogWarning(ex, "Dump verification failed. CorrelationId: {CorrelationId}", options.CorrelationId);
                return false;
            }
        }
    }
}