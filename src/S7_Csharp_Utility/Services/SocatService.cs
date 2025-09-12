using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Service for managing the socat process.
    /// </summary>
    public class SocatService
    {
        private Process? _socatProcess;
        private readonly SocatLoggerService _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="SocatService"/> class.
        /// </summary>
        /// <param name="logger">The logger service for socat.</param>
        public SocatService(SocatLoggerService logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Indicates whether the socat process is currently running.
        /// </summary>
        public bool IsRunning => _socatProcess != null && !_socatProcess.HasExited;

        /// <summary>
        /// Starts the socat process.
        /// </summary>
        /// <param name="serialPort">The serial port to connect to.</param>
        /// <param name="tcpPort">The TCP port to listen on.</param>
        public void Start(string serialPort, int tcpPort, bool verbose, bool hexDump, int blockSize)
        {
            if (IsRunning)
            {
                Stop();
            }

            _logger.Clear();
            _logger.Log($"Starting socat: TCP-LISTEN:{tcpPort} <-> {serialPort}");

            string flagArgs = string.Empty;
            if (verbose) flagArgs += "-v ";
            if (blockSize > 0) flagArgs += $"-b {blockSize} ";
            if (hexDump) flagArgs += "-x ";
            string arguments = $"{flagArgs}TCP-LISTEN:{tcpPort},fork,reuseaddr {serialPort}";

            var processStartInfo = new ProcessStartInfo
            {
                FileName = "socat",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            try
            {
                _socatProcess = Process.Start(processStartInfo);
                if (_socatProcess == null)
                {
                    throw new Exception("Failed to start socat process.");
                }

                _socatProcess.OutputDataReceived += (sender, args) => _logger.Log(args.Data);
                _socatProcess.ErrorDataReceived += (sender, args) => _logger.Log($"ERROR: {args.Data}");
                _socatProcess.BeginOutputReadLine();
                _socatProcess.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                // Handle exceptions, e.g., socat not found
                _logger.Log($"ERROR: Failed to start socat. Make sure it is installed and in the system's PATH. Error: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stops the socat process.
        /// </summary>
        public void Stop()
        {
            if (_socatProcess != null && !_socatProcess.HasExited)
            {
                _socatProcess.Kill();
                _socatProcess.WaitForExit();
            }
            _socatProcess = null;
        }
    }
}
