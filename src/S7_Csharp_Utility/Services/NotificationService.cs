using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using S7_Csharp_Utility.Interfaces;

namespace S7_Csharp_Utility.Services
{
    public class NotificationService
    {
        private static readonly Lazy<NotificationService> _instance = new(() => new NotificationService());
        public static NotificationService Instance => _instance.Value;

        private IServiceProvider? _serviceProvider;

        private NotificationService()
        {
        }

        public void Initialize(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task ShowErrorAsync(string title, string message, Exception ex)
        {
            var loggingService = _serviceProvider?.GetService<LoggingService>();
            var dialogService = _serviceProvider?.GetService<IDialogService>();

            if (loggingService != null)
            {
                loggingService.Log($"{title}: {message} - {ex}", LogCategory.Error);
            }

            if (dialogService != null)
            {
                await dialogService.ShowMessageAsync(title, message);
            }
        }
    }
}
