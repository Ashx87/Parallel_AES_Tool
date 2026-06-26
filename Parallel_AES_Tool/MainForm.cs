using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Parallel_AES_Tool
{
    internal sealed class MainForm : Form
    {
        private readonly TextBox inputPath = CreateTextBox();
        private readonly TextBox outputPath = CreateTextBox();
        private readonly TextBox password = CreateTextBox();
        private readonly NumericUpDown parallelism = new NumericUpDown();
        private readonly Button encryptButton = new Button();
        private readonly Button decryptButton = new Button();
        private readonly Button benchmarkButton = new Button();
        private readonly Label statusValue = new Label();
        private readonly DataGridView benchmarkGrid = new DataGridView();
        private readonly TextBox activityLog = new TextBox();

        public MainForm()
        {
            Text = "High-Speed Parallel File Encryption Tool using AES";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(900, 760);
            Size = new Size(1020, 800);
            BackColor = Color.FromArgb(245, 247, 250);
            Font = new Font("Segoe UI", 9F);

            BuildLayout();
            Log("Ready. Select a file, enter a password, and choose an action.");
        }

        private void BuildLayout()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.Padding = new Padding(20);
            root.ColumnCount = 1;
            root.RowCount = 4;
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            Controls.Add(root);

            Panel header = new Panel { Dock = DockStyle.Top, Height = 72, BackColor = Color.FromArgb(24, 51, 85), Margin = new Padding(0, 0, 0, 14) };
            Label title = new Label { Text = "High-Speed Parallel File Encryption Tool using AES", ForeColor = Color.White, Font = new Font("Segoe UI Semibold", 16F), AutoSize = true, Location = new Point(18, 13) };
            Label subtitle = new Label { Text = "AES-256 CTR mode | Parallel CPU processing | File integrity verification", ForeColor = Color.FromArgb(218, 229, 242), AutoSize = true, Location = new Point(20, 43) };
            header.Controls.Add(title);
            header.Controls.Add(subtitle);
            root.Controls.Add(header, 0, 0);

            GroupBox fileGroup = new GroupBox { Text = "File Encryption / Decryption", Dock = DockStyle.Top, Padding = new Padding(14), Height = 220, Margin = new Padding(0, 0, 0, 12) };
            TableLayoutPanel fileTable = CreateGrid(4);
            fileTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 105));
            fileTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            fileTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
            fileTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
            fileGroup.Controls.Add(fileTable);

            password.UseSystemPasswordChar = true;
            parallelism.Minimum = 1;
            parallelism.Maximum = 64;
            parallelism.Value = Math.Max(1, Environment.ProcessorCount);
            parallelism.Width = 100;

            AddLabeledRow(fileTable, 0, "Input file", inputPath, "Browse", delegate { BrowseInput(); });
            AddLabeledRow(fileTable, 1, "Output file", outputPath, "Save as", delegate { BrowseOutput(); });
            AddLabeledRow(fileTable, 2, "Password", password, "Clear", delegate { password.Clear(); });
            Label threadLabel = new Label { Text = "CPU threads", AutoSize = true, Anchor = AnchorStyles.Left };
            fileTable.Controls.Add(threadLabel, 0, 3);
            fileTable.Controls.Add(parallelism, 1, 3);

            FlowLayoutPanel actions = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(0, 0, 0, 0) };
            ConfigureButton(decryptButton, "Decrypt", Color.FromArgb(45, 117, 82));
            ConfigureButton(encryptButton, "Encrypt", Color.FromArgb(34, 94, 151));
            decryptButton.Click += async delegate { await RunCrypto(false); };
            encryptButton.Click += async delegate { await RunCrypto(true); };
            actions.Controls.Add(decryptButton);
            actions.Controls.Add(encryptButton);
            fileTable.Controls.Add(actions, 2, 3);
            fileTable.SetColumnSpan(actions, 2);
            root.Controls.Add(fileGroup, 0, 1);

            GroupBox benchmarkGroup = new GroupBox { Text = "Performance Benchmark - Five Parallel Strategies", Dock = DockStyle.Top, Padding = new Padding(14), Height = 275, Margin = new Padding(0, 0, 0, 12) };
            TableLayoutPanel benchmarkTable = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            benchmarkTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
            benchmarkTable.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Panel benchmarkHeader = new Panel { Dock = DockStyle.Fill };
            statusValue.Text = "Select an input file and click Run benchmark.";
            statusValue.AutoSize = true;
            statusValue.Font = new Font("Segoe UI Semibold", 9F);
            statusValue.ForeColor = Color.FromArgb(24, 51, 85);
            statusValue.Location = new Point(2, 9);
            ConfigureButton(benchmarkButton, "Run benchmark", Color.FromArgb(115, 71, 164));
            benchmarkButton.Dock = DockStyle.Right;
            benchmarkButton.AutoSize = false;
            benchmarkButton.Font = new Font("Segoe UI Semibold", 9F);
            benchmarkButton.Width = 150;
            benchmarkButton.Click += async delegate { await RunBenchmark(); };
            benchmarkHeader.Controls.Add(statusValue);
            benchmarkHeader.Controls.Add(benchmarkButton);
            benchmarkTable.Controls.Add(benchmarkHeader, 0, 0);
            ConfigureBenchmarkGrid();
            benchmarkTable.Controls.Add(benchmarkGrid, 0, 1);
            benchmarkGroup.Controls.Add(benchmarkTable);
            root.Controls.Add(benchmarkGroup, 0, 2);

            GroupBox logGroup = new GroupBox { Text = "Activity Log", Dock = DockStyle.Fill, Padding = new Padding(12) };
            activityLog.Dock = DockStyle.Fill;
            activityLog.Multiline = true;
            activityLog.ReadOnly = true;
            activityLog.ScrollBars = ScrollBars.Vertical;
            activityLog.BackColor = Color.White;
            activityLog.Font = new Font("Consolas", 9F);
            logGroup.Controls.Add(activityLog);
            root.Controls.Add(logGroup, 0, 3);
        }

        private static TextBox CreateTextBox()
        {
            return new TextBox { Dock = DockStyle.Fill, Margin = new Padding(0, 4, 8, 4) };
        }

        private static TableLayoutPanel CreateGrid(int rows)
        {
            TableLayoutPanel grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = rows };
            for (int i = 0; i < rows; i++) grid.RowStyles.Add(new RowStyle(SizeType.Percent, 25F));
            return grid;
        }

        private void AddLabeledRow(TableLayoutPanel table, int row, string label, Control field, string buttonText, EventHandler action)
        {
            table.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, 0, row);
            table.Controls.Add(field, 1, row);
            Button button = new Button { Text = buttonText, Width = 80, Height = 27, Anchor = AnchorStyles.Right };
            button.Click += action;
            table.Controls.Add(button, 2, row);
        }

        private static void ConfigureButton(Button button, string text, Color color)
        {
            button.Text = text;
            button.AutoSize = true;
            button.Height = 32;
            button.BackColor = color;
            button.ForeColor = Color.White;
            button.UseVisualStyleBackColor = false;
            button.Font = new Font("Segoe UI Semibold", 9F);
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderSize = 0;
            button.Margin = new Padding(6, 0, 0, 0);
            button.Padding = new Padding(10, 0, 10, 0);
        }

        private void ConfigureBenchmarkGrid()
        {
            benchmarkGrid.Dock = DockStyle.Fill;
            benchmarkGrid.ReadOnly = true;
            benchmarkGrid.AllowUserToAddRows = false;
            benchmarkGrid.AllowUserToDeleteRows = false;
            benchmarkGrid.AllowUserToResizeRows = false;
            benchmarkGrid.RowHeadersVisible = false;
            benchmarkGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            benchmarkGrid.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells;
            benchmarkGrid.BackgroundColor = Color.White;
            benchmarkGrid.BorderStyle = BorderStyle.FixedSingle;
            benchmarkGrid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(232, 238, 245);
            benchmarkGrid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(24, 51, 85);
            benchmarkGrid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 8.5F);
            benchmarkGrid.EnableHeadersVisualStyles = false;
            benchmarkGrid.Columns.Add("Algorithm", "Algorithm");
            benchmarkGrid.Columns.Add("Strategy", "Parallel strategy");
            benchmarkGrid.Columns.Add("Time", "Time (ms)");
            benchmarkGrid.Columns.Add("Throughput", "Throughput (MB/s)");
            benchmarkGrid.Columns.Add("Speedup", "Speedup");
            benchmarkGrid.Columns.Add("Verified", "Verified");
            benchmarkGrid.Columns[0].Width = 175;
            benchmarkGrid.Columns[1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            benchmarkGrid.Columns[2].Width = 80;
            benchmarkGrid.Columns[3].Width = 120;
            benchmarkGrid.Columns[4].Width = 80;
            benchmarkGrid.Columns[5].Width = 70;
        }

        private void BrowseInput()
        {
            using (OpenFileDialog dialog = new OpenFileDialog { Title = "Select input file", Filter = "All files (*.*)|*.*" })
            {
                if (dialog.ShowDialog(this) == DialogResult.OK)
                {
                    inputPath.Text = dialog.FileName;
                    outputPath.Text = BuildSuggestedOutputPath(dialog.FileName);
                    statusValue.Text = "File selected";
                    Log("Selected input: " + dialog.FileName);
                    Log("Suggested output: " + outputPath.Text);
                }
            }
        }

        private static string BuildSuggestedOutputPath(string selectedPath)
        {
            if (!selectedPath.EndsWith(".tpcaes", StringComparison.OrdinalIgnoreCase))
            {
                return selectedPath + ".tpcaes";
            }

            string originalPath = selectedPath.Substring(0, selectedPath.Length - 7);
            string folder = Path.GetDirectoryName(originalPath);
            string extension = Path.GetExtension(originalPath);
            string name = Path.GetFileNameWithoutExtension(originalPath);
            return Path.Combine(folder, name + "-restored" + extension);
        }

        private void BrowseOutput()
        {
            using (SaveFileDialog dialog = new SaveFileDialog { Title = "Choose output file", Filter = "All files (*.*)|*.*", FileName = Path.GetFileName(outputPath.Text) })
            {
                if (dialog.ShowDialog(this) == DialogResult.OK) outputPath.Text = dialog.FileName;
            }
        }

        private async Task RunCrypto(bool encrypt)
        {
            if (!ValidateFileAction()) return;
            if (File.Exists(outputPath.Text))
            {
                DialogResult replace = MessageBox.Show(this, "The output file already exists. Replace it?", "Confirm Replace", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (replace != DialogResult.Yes) return;
            }
            SetBusy(true, encrypt ? "Encrypting..." : "Decrypting...");
            Stopwatch timer = Stopwatch.StartNew();
            try
            {
                await Task.Run(delegate
                {
                    if (encrypt) AesCtrFile.Encrypt(inputPath.Text, outputPath.Text, password.Text, (int)parallelism.Value);
                    else AesCtrFile.Decrypt(inputPath.Text, outputPath.Text, password.Text, (int)parallelism.Value);
                });
                timer.Stop();
                statusValue.Text = encrypt ? "Encryption complete" : "Decryption complete";
                Log((encrypt ? "Encrypted" : "Decrypted") + " file in " + timer.ElapsedMilliseconds + " ms.");
                Log("Output: " + outputPath.Text);
                if (!encrypt) Log("Output SHA-256: " + Sha256(outputPath.Text));
                MessageBox.Show(this, (encrypt ? "Encryption" : "Decryption") + " completed successfully.", "AES File Tool", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                statusValue.Text = "Action failed";
                Log("Error: " + ex.Message);
                MessageBox.Show(this, ex.Message, "AES File Tool", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally { SetBusy(false, null); }
        }

        private async Task RunBenchmark()
        {
            if (String.IsNullOrWhiteSpace(inputPath.Text) || !File.Exists(inputPath.Text))
            {
                MessageBox.Show(this, "Select an existing input file before running benchmark.", "AES File Tool", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (String.IsNullOrWhiteSpace(password.Text))
            {
                MessageBox.Show(this, "Enter a password before running benchmark.", "AES File Tool", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            SetBusy(true, "Benchmarking...");
            try
            {
                BenchmarkResult result = await Task.Run(delegate { return AesCtrFile.Benchmark(inputPath.Text, password.Text, (int)parallelism.Value); });
                benchmarkGrid.Rows.Clear();
                benchmarkGrid.Rows.Add("Sequential AES-CTR", "Single worker baseline", result.SequentialMilliseconds, result.SequentialThroughputMBs.ToString("0.00"), "1.00x", "Yes");
                foreach (ParallelBenchmarkResult algorithm in result.ParallelAlgorithms)
                {
                    benchmarkGrid.Rows.Add(algorithm.Name, algorithm.Strategy, algorithm.Milliseconds, algorithm.ThroughputMBs.ToString("0.00"), algorithm.Speedup.ToString("0.00") + "x", algorithm.Verified ? "Yes" : "No");
                    Log(algorithm.Name + ": " + algorithm.Milliseconds + " ms, " + algorithm.ThroughputMBs.ToString("0.00") + " MB/s, speedup " + algorithm.Speedup.ToString("0.00") + "x, verified " + algorithm.Verified + ".");
                }
                statusValue.Text = "Benchmark complete: 4 parallel strategies verified against sequential AES-CTR.";
                Log("Benchmark completed for " + Path.GetFileName(inputPath.Text) + ". Sequential baseline: " + result.SequentialMilliseconds + " ms, " + result.SequentialThroughputMBs.ToString("0.00") + " MB/s.");
            }
            catch (Exception ex)
            {
                statusValue.Text = "Benchmark failed";
                Log("Error: " + ex.Message);
                MessageBox.Show(this, ex.Message, "AES File Tool", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally { SetBusy(false, null); }
        }

        private bool ValidateFileAction()
        {
            if (String.IsNullOrWhiteSpace(inputPath.Text) || !File.Exists(inputPath.Text))
            {
                MessageBox.Show(this, "Select an existing input file.", "AES File Tool", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            if (String.IsNullOrWhiteSpace(outputPath.Text))
            {
                MessageBox.Show(this, "Choose an output file path.", "AES File Tool", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            if (String.IsNullOrWhiteSpace(password.Text))
            {
                MessageBox.Show(this, "Enter a password.", "AES File Tool", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            if (String.Equals(Path.GetFullPath(inputPath.Text), Path.GetFullPath(outputPath.Text), StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show(this, "Output file must be different from input file.", "AES File Tool", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return false;
            }
            return true;
        }

        private void SetBusy(bool busy, string status)
        {
            encryptButton.Enabled = !busy;
            decryptButton.Enabled = !busy;
            benchmarkButton.Enabled = !busy;
            if (status != null) statusValue.Text = status;
            UseWaitCursor = busy;
        }

        private void Log(string message)
        {
            activityLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + message + Environment.NewLine);
        }

        private static string Sha256(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream stream = File.OpenRead(path))
            {
                byte[] hash = sha.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", String.Empty);
            }
        }
    }
}
