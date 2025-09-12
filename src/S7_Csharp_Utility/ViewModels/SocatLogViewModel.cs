using S7_Csharp_Utility.Services;
using System.Collections.ObjectModel;

namespace S7_Csharp_Utility.ViewModels
{
    public class SocatLogViewModel : ViewModelBase
    {
        public string LogText => _socatLogger.LogText;
        private readonly SocatLoggerService _socatLogger;

        public SocatLogViewModel(SocatLoggerService socatLogger)
        {
            _socatLogger = socatLogger;
        }
    }
}
