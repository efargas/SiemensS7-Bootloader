using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using Avalonia.Threading;

namespace S7_Csharp_Utility.Services
{
    public enum LogCategory { Info, Warning, Error, Debug }

    public class LogMessage
    {
        public DateTime Timestamp { get; set; }
        public LogCategory Category { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class LoggingService : INotifyPropertyChanged
    {
        private readonly List<LogMessage> _allLogMessages = new List<LogMessage>();
        private const int MaxLogLines = 2000;
        private readonly Dispatcher _dispatcher;
        private string _logText = string.Empty;

        public bool FilterInfo { get; set; } = true;
        public bool FilterError { get; set; } = true;
        public bool FilterDebug { get; set; } = true;

        public string LogText
        {
            get => _logText;
            private set
            {
                _logText = value;
                OnPropertyChanged();
            }
        }

        public System.Windows.Input.ICommand ClearLogCommand { get; }
        public System.Windows.Input.ICommand ExportLogCommand { get; }
        public System.Windows.Input.ICommand ScrollToEndCommand { get; }
        public event Action? ScrollToEnd;
        public event PropertyChangedEventHandler? PropertyChanged;

        public LoggingService(Dispatcher dispatcher)
        {
            _dispatcher = dispatcher;
            ClearLogCommand = new Commands.RelayCommand(_ => Clear(), _ => true);
            ExportLogCommand = new Commands.RelayCommand(_ => ExportLogs(), _ => true);
            ScrollToEndCommand = new Commands.RelayCommand(_ => ScrollToEnd?.Invoke(), _ => true);
        }

        private void ExportLogs()
        {
            string logDir = System.IO.Path.Combine(AppContext.BaseDirectory, "logs");
            System.IO.Directory.CreateDirectory(logDir);
            string logFile = System.IO.Path.Combine(logDir, $"exported_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            using (var writer = new System.IO.StreamWriter(logFile, false))
            {
                foreach (var entry in _allLogMessages)
                {
                    writer.WriteLine($"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Category} {entry.Message}");
                }
            }
        }

        public void Log(string message, LogCategory category = LogCategory.Info)
        {
            var entry = new LogMessage
            {
                Timestamp = DateTime.Now,
                Category = category,
                Message = message
            };

            _allLogMessages.Add(entry);
            if (_allLogMessages.Count > MaxLogLines)
            {
                _allLogMessages.RemoveAt(0);
            }

            _dispatcher.Post(() =>
            {
                UpdateLogFilter();
            });

            HandleLogFile(entry);
        }

        public void UpdateLogFilter()
        {
            var sb = new StringBuilder();
            
            foreach (var entry in _allLogMessages)
            {
                if ((FilterInfo && entry.Category == LogCategory.Info)
                    || (FilterError && entry.Category == LogCategory.Error)
                    || (FilterDebug && entry.Category == LogCategory.Debug)
                    || (FilterInfo && entry.Category == LogCategory.Warning))
                {
                    var categoryStr = entry.Category switch
                    {
                        LogCategory.Info => "[INFO]",
                        LogCategory.Error => "[ERROR]",
                        LogCategory.Debug => "[DEBUG]",
                        LogCategory.Warning => "[WARN]",
                        _ => "[INFO]"
                    };
                    sb.AppendLine($"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {categoryStr} {entry.Message}");
                }
            }
            
            LogText = sb.ToString();
        }

        private void HandleLogFile(LogMessage entry)
        {
            string logDir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);
            string logFile = Path.Combine(logDir, "log.txt");
            long maxSize = 5 * 1024 * 1024; // 5 MB
            if (File.Exists(logFile) && new FileInfo(logFile).Length > maxSize)
            {
                int idx = 1;
                string newLogFile;
                do
                {
                    newLogFile = Path.Combine(logDir, $"log_{idx}.txt");
                    idx++;
                }
                while (File.Exists(newLogFile));
                File.Move(logFile, newLogFile);
            }
            File.AppendAllText(logFile, $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Category} {entry.Message}{Environment.NewLine}");
        }

        public void Clear()
        {
            _allLogMessages.Clear();
            LogText = string.Empty;
        }

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
