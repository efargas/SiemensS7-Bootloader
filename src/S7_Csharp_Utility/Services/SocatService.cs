using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace S7_Csharp_Utility.Services
{
    public class SocatService
    {
        private Process? _socatProcess;
        private readonly SocatLoggerService _logger;

        public SocatService(SocatLoggerService logger)
        {
            _logger = logger;
        }

        public bool IsRunning => _socatProcess != null && !_socatProcess.HasExited;

        public void Start(string serialPort, int tcpPort)
        {
            if (IsRunning)
            {
                Stop();
            }

            _logger.Clear();
            _logger.Log($"Starting socat: TCP-LISTEN:{tcpPort} <-> {serialPort}");

            string arguments = $"TCP-LISTEN:{tcpPort},fork,reuseaddr FILE:{serialPort},raw,echo=0";

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
