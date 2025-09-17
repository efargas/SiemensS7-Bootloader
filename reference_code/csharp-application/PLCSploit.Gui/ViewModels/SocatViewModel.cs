using System;
using System.Diagnostics;
using System.Linq;
using System.Reactive;
using PLCSploit.Core;
using ReactiveUI;

namespace PLCSploit.Gui.ViewModels
{
    public class SocatViewModel : ViewModelBase
    {
        private string _serialDevice = "/dev/ttyUSB0";
        public string SerialDevice
        {
            get => _serialDevice;
            set => this.RaiseAndSetIfChanged(ref _serialDevice, value);
        }

        private string _arguments = "-v -b 4 -x TCP-LISTEN:1238,fork,reuseaddr /dev/ttyUSB0";
        public string Arguments
        {
            get => _arguments;
            set => this.RaiseAndSetIfChanged(ref _arguments, value);
        }

        private SerialSocatService _serialSocatService;

        private string _status = "Stopped";
        public string Status
        {
            get => _status;
            private set => this.RaiseAndSetIfChanged(ref _status, value);
        }

        public ReactiveCommand<Unit, Unit> StartCommand { get; }
        public ReactiveCommand<Unit, Unit> StopCommand { get; }
        public ReactiveCommand<Unit, Unit> CheckCommand { get; }
        public ReactiveCommand<Unit, Unit> KillAllCommand { get; }

        private readonly SocatViewerViewModel? _socatViewer;

        public SocatViewModel(SocatViewerViewModel? socatViewer = null)
        {
            _socatViewer = socatViewer;
            _serialSocatService = new SerialSocatService(SerialDevice, Log.Add, _socatViewer != null ? _socatViewer.AddSocatMessage : null);

            var canStart = this.WhenAnyValue(x => x.Status, (s) => s == "Stopped");
            var canStop = this.WhenAnyValue(x => x.Status, (s) => s == "Running");

            StartCommand = ReactiveCommand.Create(Start, canStart);
            StopCommand = ReactiveCommand.Create(Stop, canStop);
            CheckCommand = ReactiveCommand.Create(CheckSocatProcesses);
            KillAllCommand = ReactiveCommand.Create(KillAllSocatProcesses);

            // Update service when serial device changes
            this.WhenAnyValue(x => x.SerialDevice)
                .Subscribe(device => _serialSocatService = new SerialSocatService(device, Log.Add, _socatViewer != null ? _socatViewer.AddSocatMessage : null));
        }

        private void Start()
        {
            try
            {
                _serialSocatService.Start(Arguments);
                Status = "Running";
            }
            catch (Exception ex)
            {
                Log.Add($"ERROR: Could not start serial/socat services. Make sure stty and socat are installed and the serial device is accessible. Details: {ex.Message}");
                Status = "Error";
            }
        }

        private void Stop()
        {
            _serialSocatService.Stop();
            Status = "Stopped";
        }

        private void CheckSocatProcesses()
        {
            try
            {
                var processes = Process.GetProcessesByName("socat");
                if (processes.Length > 0)
                {
                    Log.Add($"SOCAT: Found {processes.Length} socat process(es) running:");
                    foreach (var proc in processes)
                    {
                        try
                        {
                            Log.Add($"SOCAT: PID {proc.Id} - {proc.ProcessName}");
                        }
                        catch (Exception ex)
                        {
                            Log.Add($"SOCAT: PID {proc.Id} - Could not get details: {ex.Message}");
                        }
                    }
                }
                else
                {
                    Log.Add("SOCAT: No socat processes found running");
                }
            }
            catch (Exception ex)
            {
                Log.Add($"SOCAT ERROR: Failed to check processes - {ex.Message}");
            }
        }

        private void KillAllSocatProcesses()
        {
            try
            {
                var processes = Process.GetProcessesByName("socat");
                if (processes.Length > 0)
                {
                    Log.Add($"SOCAT: Killing {processes.Length} socat process(es)...");
                    foreach (var proc in processes)
                    {
                        try
                        {
                            Log.Add($"SOCAT: Killing PID {proc.Id}");
                            proc.Kill();
                            proc.WaitForExit(2000);
                            Log.Add($"SOCAT: PID {proc.Id} terminated");
                        }
                        catch (Exception ex)
                        {
                            Log.Add($"SOCAT ERROR: Failed to kill PID {proc.Id} - {ex.Message}");
                        }
                    }
                    Status = "Stopped";
                }
                else
                {
                    Log.Add("SOCAT: No socat processes found to kill");
                }
            }
            catch (Exception ex)
            {
                Log.Add($"SOCAT ERROR: Failed to kill processes - {ex.Message}");
            }
        }
    }
}
