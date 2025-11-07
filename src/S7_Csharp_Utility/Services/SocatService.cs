using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
        
        // Store current socat configuration for restart capability
        private string? _currentSerialPort;
        private int _currentTcpPort;
        private bool _currentVerbose;
        private bool _currentHexDump;
        private int _currentBlockSize;
        private int _currentBaudRate = 38400; // Default baud rate

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
                            catch { }
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
        public static void KillAllSocatProcesses(Action<string>? log = null)
        {
            var firstPIDs = GetSocatProcessIds();
            log?.Invoke($"[SOCAT] Attempting to kill socat PIDs: {string.Join(", ", firstPIDs)}");
            foreach (var pid in firstPIDs)
            {
                try
                {
                    var proc = Process.GetProcessById(pid);
                    var processName = proc.ProcessName;
                    proc.Kill();
                    proc.WaitForExit(1000);
                    log?.Invoke($"[SOCAT] Killed socat process with PID {pid} ({processName})");
                }
                catch (Exception ex)
                {
                    log?.Invoke($"[SOCAT] Failed to kill socat process with PID {pid}: {ex.Message}");
                }
            }
            // Check again for survivors
            var remaining = GetSocatProcessIds();
            if (remaining.Length > 0)
                log?.Invoke($"[SOCAT][WARNING] The following socat PIDs are still running after kill: {string.Join(", ", remaining)}");
            else
                log?.Invoke("[SOCAT] All socat processes terminated.");
        }

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
        /// Gets the current baud rate being used by socat.
        /// </summary>
        public int CurrentBaudRate => _currentBaudRate;

        /// <summary>
        /// Starts the socat process.
        /// </summary>
        /// <param name="serialPort">The serial port to connect to.</param>
        /// <param name="tcpPort">The TCP port to listen on.</param>
        /// <param name="verbose">Enable verbose logging.</param>
        /// <param name="hexDump">Enable hex dump logging.</param>
        /// <param name="blockSize">Block size for socat.</param>
        public void Start(string serialPort, int tcpPort, bool verbose, bool hexDump, int blockSize)
        {
            StartWithBaudRate(serialPort, tcpPort, verbose, hexDump, blockSize, 38400);
        }

        /// <summary>
        /// Starts the socat process with a specific baud rate.
        /// </summary>
        /// <param name="serialPort">The serial port to connect to.</param>
        /// <param name="tcpPort">The TCP port to listen on.</param>
        /// <param name="verbose">Enable verbose logging.</param>
        /// <param name="hexDump">Enable hex dump logging.</param>
        /// <param name="blockSize">Block size for socat.</param>
        /// <param name="baudRate">Baud rate to use (38400, 57600, 115200, 230400, 460800).</param>
        public void StartWithBaudRate(string serialPort, int tcpPort, bool verbose, bool hexDump, int blockSize, int baudRate)
        {
            if (IsRunning)
            {
                Stop();
            }

            // Store current configuration for restart capability
            _currentSerialPort = serialPort;
            _currentTcpPort = tcpPort;
            _currentVerbose = verbose;
            _currentHexDump = hexDump;
            _currentBlockSize = blockSize;
            _currentBaudRate = baudRate;

            _logger.Clear();
            _logger.Log($"Starting socat: TCP-LISTEN:{tcpPort} <-> {serialPort} @ {baudRate} baud");

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
                string sttyFlags = $"cs8 {baudRate} ignbrk -brkint -icrnl -imaxbel -opost -onlcr -isig -icanon -iexten -echo -echoe -echok -echoctl -echoke -ixon -crtscts -parodd parenb raw";
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

        /// <summary>
        /// Restarts socat with a new baud rate while preserving all other settings.
        /// This is useful after reconfiguring the PLC's UART speed.
        /// </summary>
        /// <param name="newBaudRate">The new baud rate to use (38400, 57600, 115200, 230400, 460800).</param>
        /// <returns>True if restart was successful, false if socat was not previously running or restart failed.</returns>
        public bool RestartWithNewBaudRate(int newBaudRate)
        {
            if (string.IsNullOrEmpty(_currentSerialPort))
            {
                _logger.Log($"[SOCAT] Cannot restart with new baud rate: socat has never been started.");
                return false;
            }

            if (!IsRunning)
            {
                _logger.Log($"[SOCAT] Warning: socat is not currently running. Starting with new baud rate {newBaudRate}...");
            }
            else
            {
                _logger.Log($"[SOCAT] Restarting socat with new baud rate: {_currentBaudRate} → {newBaudRate}");
            }

            try
            {
                // Stop current process if running
                if (IsRunning)
                {
                    Stop();
                    // Give the system a moment to release the serial port
                    System.Threading.Thread.Sleep(500);
                }

                // Start with new baud rate but same other settings
                StartWithBaudRate(_currentSerialPort, _currentTcpPort, _currentVerbose, 
                                _currentHexDump, _currentBlockSize, newBaudRate);

                _logger.Log($"[SOCAT] ✅ Successfully restarted socat at {newBaudRate} baud");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Log($"[SOCAT] ❌ Failed to restart socat with new baud rate: {ex.Message}");
                return false;
            }
        }
    }
}
