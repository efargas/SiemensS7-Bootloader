using System.IO;
using System.Text;
using DiffPlex;
using DiffPlex.DiffBuilder;
using DiffPlex.DiffBuilder.Model;

namespace S7_Csharp_Utility.ViewModels
{
    public class DiffViewModel : ViewModelBase
    {
        private string _file1Text = string.Empty;
        public string File1Text
        {
            get => _file1Text;
            set { _file1Text = value; OnPropertyChanged(); }
        }

        private string _file2Text = string.Empty;
        public string File2Text
        {
            get => _file2Text;
            set { _file2Text = value; OnPropertyChanged(); }
        }

        public DiffViewModel(string file1Path, string file2Path)
        {
            var file1Bytes = File.ReadAllBytes(file1Path);
            var file2Bytes = File.ReadAllBytes(file2Path);

            var diffBuilder = new SideBySideDiffBuilder(new Differ());
            var diffModel = diffBuilder.BuildDiffModel(ToHex(file1Bytes), ToHex(file2Bytes));

            var sb1 = new StringBuilder();
            var sb2 = new StringBuilder();

            foreach (var line in diffModel.OldText.Lines)
            {
                sb1.AppendLine(line.Text);
            }

            foreach (var line in diffModel.NewText.Lines)
            {
                sb2.AppendLine(line.Text);
            }

            File1Text = sb1.ToString();
            File2Text = sb2.ToString();
        }

        private string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i += 16)
            {
                sb.AppendFormat("0x{0:X8}: ", i);
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < bytes.Length)
                    {
                        sb.AppendFormat("{0:X2} ", bytes[i + j]);
                    }
                    else
                    {
                        sb.Append("   ");
                    }
                }
                sb.Append(" | ");
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < bytes.Length)
                    {
                        char c = (char)bytes[i + j];
                        if (char.IsControl(c))
                        {
                            sb.Append(".");
                        }
                        else
                        {
                            sb.Append(c);
                        }
                    }
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }
    }
}
