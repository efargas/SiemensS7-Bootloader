using S7_Csharp_Utility.Interfaces;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    public class DialogService : IDialogService
    {
        public Task<string?> OpenFilePickerAsync(string title)
        {
            return Task.FromResult<string?>(null);
        }

        public Task<string?> OpenFolderPickerAsync(string title)
        {
            return Task.FromResult<string?>(null);
        }

        public Task<string?> ShowOpenFileDialogAsync(string title, string defaultExtension, string fileType)
        {
            return Task.FromResult<string?>(null);
        }

        public Task<string?> ShowSaveFileDialogAsync(string title, string defaultExtension, string fileType)
        {
            return Task.FromResult<string?>(null);
        }

        public Task ShowMessageAsync(string title, string message)
        {
            return Task.CompletedTask;
        }

        public void ShowSocatLogWindow()
        {
        }
    }
}
