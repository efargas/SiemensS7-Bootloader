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

            // Validate and normalize serial device path
            var device = serialPort?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(device))
            {
                _logger.Log("ERROR: No serial port selected. Please select a serial device before starting socat.");
                throw new ArgumentException("Serial port is required");
            }
            if (!device.StartsWith("/dev/", StringComparison.Ordinal))
            {
                device = "/dev/" + device;
            }

            string flagArgs = string.Empty;
            if (verbose) flagArgs += "-d -d -v ";
            if (blockSize > 0) flagArgs += $"-b {blockSize} ";
            if (hexDump) flagArgs += "-x ";
            // Ensure raw serial and no echo to faithfully pass bytes
            string rhs = $"{device},raw,echo=0";
            string arguments = $"{flagArgs}TCP-LISTEN:{tcpPort},fork,reuseaddr {rhs}";
            _logger.Log($"Executing: socat {arguments}");

            // On Unix platforms, set default serial parameters with stty as in reference 'start.sh'
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                string sttyFlags = "cs8 38400 ignbrk -brkint -icrnl -imaxbel -opost -onlcr -isig -icanon -iexten -echo -echoe -echok -echoctl -echoke -ixon -crtscts -parodd parenb raw";
                string sttyCmd = $"stty -F {device} {sttyFlags}";
                _logger.Log($"Executing: {sttyCmd}");
                try
                {
                    var sttyProcess = new Process()
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "/bin/bash",
                            Arguments = $"-c \"{sttyCmd}\"",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                        }
                    };
                    sttyProcess.Start();
                    sttyProcess.WaitForExit();
                    if (sttyProcess.ExitCode != 0)
                    {
                        string err = sttyProcess.StandardError.ReadToEnd();
                        _logger.Log($"WARNING: stty exited with code {sttyProcess.ExitCode}: {err}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.Log($"WARNING: Failed to run stty for serial device setup: {ex.Message}");
                }
            }

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

                _socatProcess.EnableRaisingEvents = true;
                _socatProcess.Exited += (s, e) => _logger.Log($"socat exited with code {_socatProcess.ExitCode}");

                _socatProcess.OutputDataReceived += (sender, args) => { if (args.Data != null) _logger.Log(args.Data); };
                _socatProcess.ErrorDataReceived += (sender, args) => { if (args.Data != null) _logger.Log(args.Data); };
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
