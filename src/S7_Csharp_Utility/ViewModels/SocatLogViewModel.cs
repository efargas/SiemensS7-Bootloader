using S7_Csharp_Utility.Services;
using System.Collections.ObjectModel;

namespace S7_Csharp_Utility.ViewModels
{
    public class SocatLogViewModel : ViewModelBase
    {
        public ObservableCollection<SocatLogEntry> LogEntries { get; }

        public SocatLogViewModel(SocatLoggerService socatLogger)
        {
            LogEntries = socatLogger.LogEntries;
        }
    }
}
