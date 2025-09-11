using System;
using System.Collections.ObjectModel;
using Avalonia.Threading;

namespace S7_Csharp_Utility.Services
{
    public class SocatLoggerService
    {
        private readonly Dispatcher _dispatcher;
        public ObservableCollection<string> LogEntries { get; } = new ObservableCollection<string>();

        public SocatLoggerService(Dispatcher dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public void Log(string? data)
        {
            if (data != null)
            {
                _dispatcher.Post(() => LogEntries.Add(data));
            }
        }

        public void Clear()
        {
            _dispatcher.Post(() => LogEntries.Clear());
        }
    }
}
