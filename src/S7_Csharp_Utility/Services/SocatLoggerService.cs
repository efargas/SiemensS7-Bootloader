using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using Avalonia.Threading;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Represents a single socat log entry.
    /// </summary>
    public class SocatLogEntry
    {
        /// <summary>
        /// The timestamp of the log entry.
        /// </summary>
        public DateTime Timestamp { get; set; }
        /// <summary>
        /// The content of the log entry.
        /// </summary>
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Service for handling socat logging.
    /// </summary>
    public class SocatLoggerService : INotifyPropertyChanged
    {
        private readonly Dispatcher _dispatcher;
        private readonly List<SocatLogEntry> _logEntries = new List<SocatLogEntry>();
        private readonly object _sync = new object();
        private string _logText = string.Empty;
        private const int MaxLogLines = 2000;

        public System.Windows.Input.ICommand ClearLogCommand { get; }
        public System.Windows.Input.ICommand ExportLogCommand { get; }
        public System.Windows.Input.ICommand ScrollToEndCommand { get; }
        public event Action? ScrollToEnd;

        /// <summary>
        /// The formatted log text to be displayed in the UI.
        /// </summary>
        public string LogText
        {
            get => _logText;
            private set
            {
                _logText = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Event triggered when a property value changes.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Initializes a new instance of the <see cref="SocatLoggerService"/> class.
        /// </summary>
        /// <param name="dispatcher">The dispatcher to use for UI updates.</param>
        public SocatLoggerService(Dispatcher dispatcher)
        {
            _dispatcher = dispatcher;
            ClearLogCommand = new Commands.RelayCommand(_ => Clear(), _ => true);
            ExportLogCommand = new Commands.RelayCommand(_ => ExportLogs(), _ => true);
            ScrollToEndCommand = new Commands.RelayCommand(_ => ScrollToEnd?.Invoke(), _ => true);
        }

        /// <summary>
        /// Logs a message from the socat process.
        /// </summary>
        /// <param name="data">The message to log.</param>
        public void Log(string? data)
        {
            if (data == null) return;

            lock (_sync)
            {
                var entry = new SocatLogEntry { Timestamp = DateTime.Now, Message = data };
                _logEntries.Add(entry);
                if (_logEntries.Count > MaxLogLines)
                {
                    _logEntries.RemoveAt(0);
                }
            }

            _dispatcher.Post(UpdateLogText);
        }

        /// <summary>
        /// Updates the log text to be displayed in the UI.
        /// </summary>
        private void UpdateLogText()
        {
            List<SocatLogEntry> snapshot;
            lock (_sync)
            {
                snapshot = new List<SocatLogEntry>(_logEntries);
            }

            var sb = new StringBuilder();
            foreach (var entry in snapshot)
            {
                sb.AppendLine($"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Message}");
            }
            LogText = sb.ToString();
        }

        /// <summary>
        /// Clears the socat log.
        /// </summary>
        public void Clear()
        {
            _dispatcher.Post(() =>
            {
                lock (_sync)
                {
                    _logEntries.Clear();
                }
                LogText = string.Empty;
            });
        }

        /// <summary>
        /// Exports the socat log to a text file.
        /// </summary>
        private void ExportLogs()
        {
            string logDir = System.IO.Path.Combine(AppContext.BaseDirectory, "logs");
            System.IO.Directory.CreateDirectory(logDir);
            string logFile = System.IO.Path.Combine(logDir, $"socat_exported_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            List<SocatLogEntry> snapshot;
            lock (_sync)
            {
                snapshot = new List<SocatLogEntry>(_logEntries);
            }
            using (var writer = new System.IO.StreamWriter(logFile, false))
            {
                foreach (var entry in snapshot)
                {
                    writer.WriteLine($"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Message}");
                }
            }
        }

        /// <summary>
        /// Triggers the PropertyChanged event.
        /// </summary>
        /// <param name="propertyName">The name of the property that changed.</param>
        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
