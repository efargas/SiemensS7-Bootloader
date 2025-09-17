using System;
using System.Reactive;
using System.Threading.Tasks;
using PLCSploit.Core;
using ReactiveUI;

namespace PLCSploit.Gui.ViewModels
{
    public class ModbusViewModel : ViewModelBase
    {
        private string _host = "192.168.1.18";
        public string Host
        {
            get => _host;
            set => this.RaiseAndSetIfChanged(ref _host, value);
        }

        private int _port = 502;
        public int Port
        {
            get => _port;
            set => this.RaiseAndSetIfChanged(ref _port, value);
        }

        private int _delay = 1000;
        public int Delay
        {
            get => _delay;
            set => this.RaiseAndSetIfChanged(ref _delay, value);
        }

        private PowerSupply? _powerSupply;

        private string _status = "Disconnected";
        public string Status
        {
            get => _status;
            private set => this.RaiseAndSetIfChanged(ref _status, value);
        }

        public ReactiveCommand<Unit, Unit> ConnectCommand { get; }
        public ReactiveCommand<Unit, Unit> DisconnectCommand { get; }
        public ReactiveCommand<Unit, Unit> TurnOnCommand { get; }
        public ReactiveCommand<Unit, Unit> TurnOffCommand { get; }

        public ModbusViewModel()
        {
            var canConnect = this.WhenAnyValue(x => x.Status, (status) => status == "Disconnected");
            var canDisconnect = this.WhenAnyValue(x => x.Status, (status) => status == "Connected");

            ConnectCommand = ReactiveCommand.Create(Connect, canConnect);
            DisconnectCommand = ReactiveCommand.Create(Disconnect, canDisconnect);
            TurnOnCommand = ReactiveCommand.CreateFromTask(TurnOnAsync, canDisconnect);
            TurnOffCommand = ReactiveCommand.CreateFromTask(TurnOffAsync, canDisconnect);
        }

        private void Connect()
        {
            _powerSupply = new PowerSupply(Host, Port, Log.Add);
            try
            {
                _powerSupply.Connect();
                Status = "Connected";
            }
            catch (Exception ex)
            {
                Log.Add($"ERROR: {ex.Message}");
            }
        }

        private void Disconnect()
        {
            _powerSupply?.Disconnect();
            Status = "Disconnected";
        }

        private async Task TurnOnAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    _powerSupply?.TurnOn();
                }
                catch (Exception ex)
                {
                    Log.Add($"ERROR: {ex.Message}");
                }
            });
        }

        private async Task TurnOffAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    _powerSupply?.TurnOff();
                }
                catch (Exception ex)
                {
                    Log.Add($"ERROR: {ex.Message}");
                }
            });
        }
    }
}
