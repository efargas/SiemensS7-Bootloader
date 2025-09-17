using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace PLCSploit.Core
{
    public class SocatService
    {
        private Process _process;
        private readonly Action<string, LogCategory> _logger;

        public bool IsRunning => _process != null && !_process.HasExited;

        public SocatService(Action<string, LogCategory> logger = null)
        {
            _logger = logger ?? ((msg, cat) => Log.Add(msg, cat));
        }

        public void Start(string arguments)
        {
            if (IsRunning) return;

            var startInfo = new ProcessStartInfo
            {
                FileName = "socat",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            _process = new Process { StartInfo = startInfo };

            _process.OutputDataReceived += (sender, args) => { if (args.Data != null) _logger($"[socat] {args.Data}", LogCategory.Communication); };
            _process.ErrorDataReceived += (sender, args) => { if (args.Data != null) _logger($"[socat ERR] {args.Data}", LogCategory.Error); };

            _logger($"Starting socat with arguments: {arguments}", LogCategory.Communication);
            _process.Start();
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
        }

        public void Stop()
        {
            if (!IsRunning) return;

            _logger("Stopping socat...", LogCategory.Communication);
            _process.Kill();
            _process = null;
            _logger("socat stopped.", LogCategory.Info);
        }
    }
}
