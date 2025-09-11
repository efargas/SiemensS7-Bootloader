using S7_Csharp_Utility.Services;
using System.Windows.Input;
using System.Threading.Tasks;
using System;

namespace S7_Csharp_Utility.ViewModels
{
    public class MainWindowViewModel : ViewModelBase
    {
        private string _plcHost = "localhost";
        public string PlcHost
        {
            get => _plcHost;
            set
            {
                _plcHost = value;
                OnPropertyChanged();
            }
        }

        private int _plcPort = 102;
        public int PlcPort
        {
            get => _plcPort;
            set
            {
                _plcPort = value;
                OnPropertyChanged();
            }
        }

        private string _modbusHost = "localhost";
        public string ModbusHost
        {
            get => _modbusHost;
            set
            {
                _modbusHost = value;
                OnPropertyChanged();
            }
        }

        private int _modbusPort = 502;
        public int ModbusPort
        {
            get => _modbusPort;
            set
            {
                _modbusPort = value;
                OnPropertyChanged();
            }
        }

        private ushort _modbusCoil = 1;
        public ushort ModbusCoil
        {
            get => _modbusCoil;
            set
            {
                _modbusCoil = value;
                OnPropertyChanged();
            }
        }

        public LoggingService Logging { get; }
        private readonly PowerController _powerController;

        public ICommand PowerOnCommand { get; }
        public ICommand PowerOffCommand { get; }

        private readonly S7.Net.PlcClient _plcClient;
        private readonly S7.Net.PayloadManager _payloadManager;

        private string _dumpAddress = "0x10000000";
        public string DumpAddress
        {
            get => _dumpAddress;
            set
            {
                _dumpAddress = value;
                OnPropertyChanged();
            }
        }

        private uint _dumpLength = 4096;
        public uint DumpLength
        {
            get => _dumpLength;
            set
            {
                _dumpLength = value;
                OnPropertyChanged();
            }
        }


        private bool _isBusy;
        public bool IsBusy
        {
            get => _isBusy;
            set
            {
                _isBusy = value;
                OnPropertyChanged();
                (UploadStagerCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
                (DumpMemoryCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        private bool _stagerInstalled;
        public bool StagerInstalled
        {
            get => _stagerInstalled;
            set
            {
                _stagerInstalled = value;
                OnPropertyChanged();
                (DumpMemoryCommand as Commands.RelayCommand)?.RaiseCanExecuteChanged();
            }
        }

        public ICommand UploadStagerCommand { get; }
        public ICommand DumpMemoryCommand { get; }

        public MainWindowViewModel(LoggingService loggingService, PowerController powerController, S7.Net.PlcClient plcClient, S7.Net.PayloadManager payloadManager)
        {
            Logging = loggingService;
            _powerController = powerController;
            _plcClient = plcClient;
            _payloadManager = payloadManager;

            PowerOnCommand = new Commands.RelayCommand(async _ => await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, true));
            PowerOffCommand = new Commands.RelayCommand(async _ => await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, false));
            UploadStagerCommand = new Commands.RelayCommand(async _ => await UploadStager(), _ => !IsBusy);
            DumpMemoryCommand = new Commands.RelayCommand(async _ => await DumpMemory(), _ => !IsBusy && StagerInstalled);
        }

        private async Task UploadStager()
        {
            IsBusy = true;
            try
            {
                await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, false);
                //int delaySeconds = (int)(DelayNumericUpDown.Value ?? 1); // This needs to be a property
                int delaySeconds = 1;
                Logging.Log($"Waiting for {delaySeconds} seconds before powering on...", LogCategory.Info);
                await Task.Delay(delaySeconds * 1000);
                await _powerController.SetPowerAsync(ModbusHost, ModbusPort, ModbusCoil, true);

                await Task.Delay(50);

                await RunStagerSequenceAsync();
            }
            catch (Exception ex)
            {
                Logging.Log($"An error occurred during the stager sequence: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                if (_plcClient.IsConnected)
                {
                    _plcClient.Disconnect();
                }
                IsBusy = false;
            }
        }

        private async Task RunStagerSequenceAsync()
        {
            StagerInstalled = false;
            await _plcClient.ConnectAsync(PlcHost, PlcPort);
            if (!_plcClient.IsConnected) return;

            if (await _plcClient.PerformHandshakeAsync())
            {
                await _plcClient.GetVersion();

                byte[] stagerPayload = _payloadManager.GetStagerPayload();
                Logging.Log($"Loaded stager payload ({stagerPayload.Length} bytes).", LogCategory.Info);

                await _plcClient.InstallStager(stagerPayload);
                StagerInstalled = true;
                Logging.Log("Stager is installed and ready.", LogCategory.Info);
            }
        }

        private async Task DumpMemory()
        {
            IsBusy = true;
            try
            {
                if (!uint.TryParse(DumpAddress.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.CurrentCulture, out uint address))
                {
                    Logging.Log("Error: Invalid dump address. Must be a valid hex number (e.g., 0x10000000).", LogCategory.Error);
                    return;
                }
                if (DumpLength == 0)
                {
                    Logging.Log("Error: Invalid dump length. Must be a positive number.", LogCategory.Error);
                    return;
                }

                await RunDumpSequenceAsync(address, DumpLength);
            }
            catch (Exception ex)
            {
                Logging.Log($"An error occurred during the dump sequence: {ex.Message}", LogCategory.Error);
            }
            finally
            {
                IsBusy = false;
            }
        }

        private async Task RunDumpSequenceAsync(uint address, uint length)
        {
            Logging.Log($"Starting memory dump of {length} bytes from 0x{address:X8}...", LogCategory.Info);

            byte[] dumperPayload = _payloadManager.GetMemoryDumperPayload();
            Logging.Log($"Loaded dumper payload ({dumperPayload.Length} bytes).", LogCategory.Info);

            int dumperHookIndex = 0x1a;
            await _plcClient.InstallAddHookViaStager(0x10010100, dumperPayload, dumperHookIndex);
            Logging.Log("Memory dumper payload installed.", LogCategory.Info);

            var args = new byte[1 + 4 + 4];
            args[0] = (byte)'A';
            BitConverter.GetBytes(address).CopyTo(args, 1);
            BitConverter.GetBytes(length).CopyTo(args, 5);

            await _plcClient.InvokeAddHook(dumperHookIndex, args);
            Logging.Log("Dump command sent. Receiving data...", LogCategory.Info);

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var progress = new Progress<long>(bytesRead =>
            {
                // UI update logic for progress should be here
            });

            var dumpedData = await _plcClient.ReceiveMany(progress);
            stopwatch.Stop();

            string outFilename = $"mem_dump_{address:x8}_{address + length:x8}.bin";
            await System.IO.File.WriteAllBytesAsync(outFilename, dumpedData);
            Logging.Log($"Successfully dumped {dumpedData.Length} bytes to {outFilename} in {stopwatch.Elapsed.TotalSeconds:F1}s.", LogCategory.Info);
        }
    }
}
