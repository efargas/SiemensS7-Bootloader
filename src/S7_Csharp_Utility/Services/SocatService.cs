using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using S7_Csharp_Utility.Interfaces;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Service for managing the socat process.
    /// </summary>
    public class SocatService : ISocatService
    {
        private Process? _socatProcess;
        private readonly ILogger<SocatService> _logger;

        /// <summary>
        /// Gets all running socat process IDs as an array.
        /// </summary>
        public static int[] GetSocatProcessIds()
        {
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return Process.GetProcessesByName("socat").Select(p => p.Id).ToArray();
                }
                else
                {
                    var list = new System.Collections.Generic.List<int>();
                    foreach (var dir in Directory.GetDirectories("/proc"))
                    {
                        if (int.TryParse(Path.GetFileName(dir), out int pid))
                        {
                            try
                            {
                                string cmdline = File.ReadAllText(Path.Combine(dir, "cmdline"));
                                if (cmdline.Contains("socat"))
                                {
                                    list.Add(pid);
                                }
                            }
                            catch { /* Ignore errors reading cmdline */ }
                        }
                    }
                    return list.ToArray();
                }
            }
            catch
            {
                return Array.Empty<int>();
            }
        }

        /// <summary>
        /// Kills all running socat processes.
        /// </summary>
        public static void KillAllSocatProcesses(ILogger? logger = null)
        {
            var firstPIDs = GetSocatProcessIds();
            logger?.LogInformation("[SOCAT] Attempting to kill socat PIDs: {PIDs}", string.Join(", ", firstPIDs));
            foreach (var pid in firstPIDs)
            {
                try
                {
                    var proc = Process.GetProcessById(pid);
                    var processName = proc.ProcessName;
                    proc.Kill();
                    proc.WaitForExit(1000);
                    logger?.LogInformation("[SOCAT] Killed socat process with PID {PID} ({ProcessName})", pid, processName);
                }
                catch (Exception ex)
                {
                    logger?.LogError(ex, "[SOCAT] Failed to kill socat process with PID {PID}", pid);
                }
            }
            // Check again for survivors
            var remaining = GetSocatProcessIds();
            if (remaining.Length > 0)
                logger?.LogWarning("[SOCAT] The following socat PIDs are still running after kill: {PIDs}", string.Join(", ", remaining));
            else
                logger?.LogInformation("[SOCAT] All socat processes terminated.");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SocatService"/> class.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        public SocatService(ILogger<SocatService> logger)
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
        public void Start(string serialPort, int tcpPort, bool verbose, bool hexDump, int blockSize)
        {
            if (IsRunning)
            {
                Stop();
            }

            _logger.LogInformation("Starting socat: TCP-LISTEN:{TcpPort} <-> {SerialPort}", tcpPort, serialPort);

            var device = serialPort?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(device))
            {
                _logger.LogError("No serial port selected. Please select a serial device before starting socat.");
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
            string rhs = $"{device},raw,echo=0";
            string arguments = $"{flagArgs}TCP-LISTEN:{tcpPort},fork,reuseaddr {rhs}";
            _logger.LogInformation("Executing: socat {Arguments}", arguments);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                string sttyFlags = "cs8 38400 ignbrk -brkint -icrnl -imaxbel -opost -onlcr -isig -icanon -iexten -echo -echoe -echok -echoctl -echoke -ixon -crtscts -parodd parenb raw";
                string sttyCmd = $"stty -F {device} {sttyFlags}";
                _logger.LogInformation("Executing: {SttyCmd}", sttyCmd);
                try
                {
                    var sttyProcess = new Process
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
                        _logger.LogWarning("stty exited with code {ExitCode}: {Error}", sttyProcess.ExitCode, err);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to run stty for serial device setup.");
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
                    throw new InvalidOperationException("Failed to start socat process.");
                }

                _socatProcess.EnableRaisingEvents = true;
                _socatProcess.Exited += (s, e) => _logger.LogInformation("socat exited with code {ExitCode}", _socatProcess.ExitCode);

                _socatProcess.OutputDataReceived += (sender, args) => { if (args.Data != null) _logger.LogInformation("{SocatOutput}", args.Data); };
                _socatProcess.ErrorDataReceived += (sender, args) => { if (args.Data != null) _logger.LogError("{SocatError}", args.Data); };
                _socatProcess.BeginOutputReadLine();
                _socatProcess.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to start socat. Make sure it is installed and in the system's PATH.");
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