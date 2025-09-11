using S7_Csharp_Utility.Models;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Services
{
    public class ConfigurationService
    {
        public async Task SaveConfiguration(ApplicationConfiguration config, string filePath)
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(config, options);
            await File.WriteAllTextAsync(filePath, json);
        }

        public async Task<ApplicationConfiguration?> LoadConfiguration(string filePath)
        {
            if (!File.Exists(filePath))
            {
                return null;
            }

            string json = await File.ReadAllTextAsync(filePath);
            return JsonSerializer.Deserialize<ApplicationConfiguration>(json);
        }
    }
}
