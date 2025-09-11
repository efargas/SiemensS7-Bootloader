using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using System.Text.Json;
using System.Collections.ObjectModel;
using System.IO;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace S7_Csharp_Utility
{
    public partial class ProfileManagementWindow : Window
    {
        private DeviceProfile? _currentProfile = new DeviceProfile();
        private ObservableCollection<MemoryRegion> _profileRegions = new ObservableCollection<MemoryRegion>();

        public ProfileManagementWindow()
        {
            InitializeComponent();
            RegionsDataGrid.ItemsSource = _profileRegions;
            LoadProfileButton.Click += LoadProfileButton_Click;
            SaveProfileButton.Click += SaveProfileButton_Click;
        }

        private async void LoadProfileButton_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return;
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Open Profile File",
                AllowMultiple = false,
                FileTypeFilter = new[] { new FilePickerFileType("JSON Profiles") { Patterns = new[] { "*.json" } } }
            });

            if (files.Count >= 1)
            {
                try
                {
                    await using var stream = await files[0].OpenReadAsync();
                    using var reader = new StreamReader(stream);
                    string json = await reader.ReadToEndAsync();
                    _currentProfile = JsonSerializer.Deserialize<DeviceProfile>(json);
                    if (_currentProfile != null)
                    {
                        ProfileModelNameTextBox.Text = _currentProfile.ModelName;
                        _profileRegions.Clear();
                        foreach (var region in _currentProfile.Regions)
                            _profileRegions.Add(region);
                    }
                }
                catch (Exception ex)
                {
                    await ShowMessage($"Error loading profile: {ex.Message}");
                }
            }
        }

        private async void SaveProfileButton_Click(object? sender, RoutedEventArgs e)
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null) return;
            var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Save Profile File",
                DefaultExtension = "json",
                FileTypeChoices = new[] { new FilePickerFileType("JSON Profiles") { Patterns = new[] { "*.json" } } }
            });

            if (file is not null)
            {
                var profileToSave = new DeviceProfile { ModelName = ProfileModelNameTextBox.Text ?? string.Empty, Regions = _profileRegions.ToList() };
                try
                {
                    var options = new JsonSerializerOptions { WriteIndented = true };
                    string json = JsonSerializer.Serialize(profileToSave, options);
                    await using var stream = await file.OpenWriteAsync();
                    using var writer = new StreamWriter(stream);
                    await writer.WriteAsync(json);
                }
                catch (Exception ex)
                {
                    await ShowMessage($"Error saving profile: {ex.Message}");
                }
            }
        }

        private async Task ShowMessage(string msg)
        {
            var dlg = new Window { Title = "Info", Content = new TextBlock { Text = msg, Margin = new Avalonia.Thickness(12) }, Width = 360, Height = 120 };
            await dlg.ShowDialog(this);
        }
    }
}
