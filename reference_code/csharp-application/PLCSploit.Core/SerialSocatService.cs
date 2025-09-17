using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace PLCSploit.Core
{
    public class SerialSocatService
    {
        private Process _socatProcess;
        private readonly Action<string, LogCategory> _logger;
        private readonly Action<string> _socatLogger;
        private readonly string _serialDevice;

        public bool IsRunning => _socatProcess != null && !_socatProcess.HasExited;

        public SerialSocatService(string serialDevice = "/dev/ttyUSB0", Action<string, LogCategory> logger = null, Action<string> socatLogger = null)
        {
            _serialDevice = serialDevice;
            _logger = logger ?? ((msg, cat) => Log.Add(msg, cat));
            _socatLogger = socatLogger ?? (msg => { });
        }

        public void Start(string socatArguments)
        {
            if (IsRunning) return;

            // First configure the serial device with stty
            ConfigureSerialDevice();

            // Then start socat
            StartSocat(socatArguments);
        }

        private void ConfigureSerialDevice()
        {
            try
            {
                var sttyArgs = $"-F {_serialDevice} cs8 38400 ignbrk -brkint -icrnl -imaxbel -opost -onlcr -isig -icanon -iexten -echo -echoe -echok -echoctl -echoke -ixon -crtscts -parodd parenb raw";
                
                var startInfo = new ProcessStartInfo
                {
                    FileName = "stty",
                    Arguments = sttyArgs,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };

                Log.Add($"Configuring serial device {_serialDevice} with stty...", LogCategory.Communication);
                
                using (var sttyProcess = new Process { StartInfo = startInfo })
                {
                    sttyProcess.Start();
                    var output = sttyProcess.StandardOutput.ReadToEnd();
                    var error = sttyProcess.StandardError.ReadToEnd();
                    sttyProcess.WaitForExit();

                    if (sttyProcess.ExitCode == 0)
                    {
                        Log.Add($"Serial device {_serialDevice} configured successfully", LogCategory.Info);
                    }
                    else
                    {
                        Log.Add($"stty configuration failed with exit code {sttyProcess.ExitCode}", LogCategory.Error);
                        if (!string.IsNullOrEmpty(error))
                            Log.Add($"stty error: {error}", LogCategory.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Add($"ERROR configuring serial device: {ex.Message}", LogCategory.Error);
                throw;
            }
        }

        private void StartSocat(string arguments)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "socat",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };

                _socatProcess = new Process { StartInfo = startInfo };

                Log.Add($"Starting socat with arguments: {arguments}", LogCategory.Communication);
                _socatProcess.Start();

                Task.Run(() => ReadOutputStream(_socatProcess));
                Task.Run(() => ReadErrorStream(_socatProcess));
            }
            catch (Exception ex)
            {
                Log.Add($"ERROR starting socat: {ex.Message}", LogCategory.Error);
                throw;
            }
        }

        public void Stop()
        {
            if (!IsRunning) return;

            Log.Add("Stopping socat...", LogCategory.Communication);
            try
            {
                _socatProcess.Kill();
                _socatProcess.WaitForExit(5000); // Wait up to 5 seconds
                _socatProcess?.Dispose();
                _socatProcess = null;
                Log.Add("socat stopped.", LogCategory.Info);
            }
            catch (Exception ex)
            {
                Log.Add($"Error stopping socat: {ex.Message}", LogCategory.Error);
            }
        }

        private async Task ReadOutputStream(Process process)
        {
            using (var reader = process.StandardOutput)
            {
                while (!process.HasExited)
                {
                    var line = await reader.ReadLineAsync();
                    if (line != null)
                    {
                        var generalMessage = $"[socat] {line}";
                        var socatMessage = $"STDOUT: {line}";
                        _logger(generalMessage, LogCategory.Communication);
                        _socatLogger?.Invoke(socatMessage);
                    }
                }
            }
        }

        private async Task ReadErrorStream(Process process)
        {
            using (var reader = process.StandardError)
            {
                while (!process.HasExited)
                {
                    var line = await reader.ReadLineAsync();
                    if (line != null)
                    {
                        var generalMessage = $"[socat ERR] {line}";
                        var socatMessage = $"STDERR: {line}";
                        _logger(generalMessage, LogCategory.Error);
                        _socatLogger?.Invoke(socatMessage);
                    }
                }
            }
        }
    }
}
