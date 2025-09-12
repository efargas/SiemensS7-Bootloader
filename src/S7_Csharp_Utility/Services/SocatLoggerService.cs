using System;
using System.Collections.ObjectModel;
using Avalonia.Threading;

namespace S7_Csharp_Utility.Services
{
    public class SocatLogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class SocatLoggerService
    {
        private readonly Dispatcher _dispatcher;
        public ObservableCollection<SocatLogEntry> LogEntries { get; } = new ObservableCollection<SocatLogEntry>();

        public SocatLoggerService(Dispatcher dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public void Log(string? data)
        {
            if (data != null)
            {
                var entry = new SocatLogEntry { Timestamp = DateTime.Now, Message = data };
                _dispatcher.Post(() => LogEntries.Add(entry));
            }
        }

        public void Clear()
        {
            _dispatcher.Post(() => LogEntries.Clear());
        }
    }
}
