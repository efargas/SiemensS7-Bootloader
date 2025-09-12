using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using Avalonia.Threading;

namespace S7_Csharp_Utility.Services
{
    public class SocatLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class SocatLoggerService : INotifyPropertyChanged
    {
        private readonly Dispatcher _dispatcher;
        private readonly List<SocatLogEntry> _logEntries = new List<SocatLogEntry>();
        private string _logText = string.Empty;
        private const int MaxLogLines = 2000;

        public string LogText
        {
            get => _logText;
            private set
            {
                _logText = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public SocatLoggerService(Dispatcher dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public void Log(string? data)
        {
            if (data != null)
            {
                var entry = new SocatLogEntry { Timestamp = DateTime.Now, Message = data };
                
                _logEntries.Add(entry);
                if (_logEntries.Count > MaxLogLines)
                {
                    _logEntries.RemoveAt(0);
                }

                _dispatcher.Post(() => 
                {
                    UpdateLogText();
                });
            }
        }

        private void UpdateLogText()
        {
            var sb = new StringBuilder();
            foreach (var entry in _logEntries)
            {
                sb.AppendLine($"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Message}");
            }
            LogText = sb.ToString();
        }

        public void Clear()
        {
            _dispatcher.Post(() => 
            {
                _logEntries.Clear();
                LogText = string.Empty;
            });
        }

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
