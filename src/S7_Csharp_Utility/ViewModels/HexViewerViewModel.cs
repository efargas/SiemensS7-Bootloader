using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using S7_Csharp_Utility.Commands;
using S7_Csharp_Utility.Interfaces;
using S7_Csharp_Utility.Services;

namespace S7_Csharp_Utility.ViewModels
{
    public class HexViewerViewModel : ViewModelBase
    {
        public ObservableCollection<HexRow> HexRows1 { get; } = new ObservableCollection<HexRow>();
        public ObservableCollection<HexRow> HexRows2 { get; } = new ObservableCollection<HexRow>();
        public ICommand LoadSecondFileCommand { get; }
        private readonly IDialogService _dialogService;

        private bool _isLittleEndian = true;
        public bool IsLittleEndian
        {
            get => _isLittleEndian;
            set
            {
                if (SetProperty(ref _isLittleEndian, value))
                {
                    UpdateInspectorPanel();
                }
            }
        }

        private byte[] _selectedBytes = Array.Empty<byte>();
        public byte[] SelectedBytes
        {
            get => _selectedBytes;
            set
            {
                if (SetProperty(ref _selectedBytes, value))
                {
                    UpdateInspectorPanel();
                }
            }
        }

        #region Inspector Properties
        private string _stringValue = string.Empty;
        public string StringValue { get => _stringValue; set => SetProperty(ref _stringValue, value); }

        private string _charValue = string.Empty;
        public string CharValue { get => _charValue; set => SetProperty(ref _charValue, value); }

        private sbyte _int8Value;
        public sbyte Int8Value { get => _int8Value; set => SetProperty(ref _int8Value, value); }

        private byte _uint8Value;
        public byte UInt8Value { get => _uint8Value; set => SetProperty(ref _uint8Value, value); }

        private short _int16Value;
        public short Int16Value { get => _int16Value; set => SetProperty(ref _int16Value, value); }

        private ushort _uint16Value;
        public ushort UInt16Value { get => _uint16Value; set => SetProperty(ref _uint16Value, value); }

        private int _int32Value;
        public int Int32Value { get => _int32Value; set => SetProperty(ref _int32Value, value); }

        private uint _uint32Value;
        public uint UInt32Value { get => _uint32Value; set => SetProperty(ref _uint32Value, value); }

        private long _int64Value;
        public long Int64Value { get => _int64Value; set => SetProperty(ref _int64Value, value); }

        private ulong _uint64Value;
        public ulong UInt64Value { get => _uint64Value; set => SetProperty(ref _uint64Value, value); }
        #endregion

        public HexViewerViewModel()
        {
            _dialogService = new DialogService(); // Use a default implementation
            LoadSecondFileCommand = new AsyncRelayCommand(async _ => await LoadSecondFile());
        }

        public async Task LoadFileAsync(string filePath, int gridNumber = 1)
        {
            var collection = gridNumber == 1 ? HexRows1 : HexRows2;
            collection.Clear();
            if (!File.Exists(filePath)) return;

            await Task.Run(() =>
            {
                var bytes = File.ReadAllBytes(filePath);
                for (int i = 0; i < bytes.Length; i += 16)
                {
                    var slice = bytes.Skip(i).Take(16).ToArray();
                    var row = new HexRow
                    {
                        Address = $"{i:X8}",
                        Hex = string.Join(" ", slice.Select(b => b.ToString("X2"))),
                        Ascii = new string(slice.Select(b => (char.IsControl((char)b) ? '.' : (char)b)).ToArray())
                    };
                    Avalonia.Threading.Dispatcher.UIThread.Post(() => collection.Add(row));
                }
            });
        }

        private async Task LoadSecondFile()
        {
            var filePath = await _dialogService.ShowOpenFileDialogAsync("Select Second File", "*", "All Files");
            if (filePath != null)
            {
                await LoadFileAsync(filePath, 2);
            }
        }

        private void UpdateInspectorPanel()
        {
            if (SelectedBytes == null || SelectedBytes.Length == 0)
            {
                StringValue = string.Empty;
                CharValue = string.Empty;
                Int8Value = 0;
                UInt8Value = 0;
                Int16Value = 0;
                UInt16Value = 0;
                Int32Value = 0;
                UInt32Value = 0;
                Int64Value = 0;
                UInt64Value = 0;
                return;
            }

            StringValue = Encoding.ASCII.GetString(SelectedBytes);
            CharValue = SelectedBytes.Length > 0 ? ((char)SelectedBytes[0]).ToString() : string.Empty;

            Int8Value = SelectedBytes.Length >= 1 ? (sbyte)SelectedBytes[0] : (sbyte)0;
            UInt8Value = SelectedBytes.Length >= 1 ? SelectedBytes[0] : (byte)0;

            var bytes = (byte[])SelectedBytes.Clone();
            if (!IsLittleEndian) Array.Reverse(bytes);

            Int16Value = SelectedBytes.Length >= 2 ? BitConverter.ToInt16(bytes, 0) : (short)0;
            UInt16Value = SelectedBytes.Length >= 2 ? BitConverter.ToUInt16(bytes, 0) : (ushort)0;
            Int32Value = SelectedBytes.Length >= 4 ? BitConverter.ToInt32(bytes, 0) : 0;
            UInt32Value = SelectedBytes.Length >= 4 ? BitConverter.ToUInt32(bytes, 0) : 0;
            Int64Value = SelectedBytes.Length >= 8 ? BitConverter.ToInt64(bytes, 0) : 0;
            UInt64Value = SelectedBytes.Length >= 8 ? BitConverter.ToUInt64(bytes, 0) : 0;
        }
    }

    public class HexRow
    {
        public string? Address { get; set; }
        public string? Hex { get; set; }
        public string? Ascii { get; set; }
    }
}
