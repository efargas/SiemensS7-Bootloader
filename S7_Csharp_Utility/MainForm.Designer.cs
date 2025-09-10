namespace S7_Csharp_Utility
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.plcSettingsBox = new System.Windows.Forms.GroupBox();
            this.plcPortLabel = new System.Windows.Forms.Label();
            this.plcHostLabel = new System.Windows.Forms.Label();
            this.plcPortTextBox = new System.Windows.Forms.TextBox();
            this.plcHostTextBox = new System.Windows.Forms.TextBox();

            this.modbusSettingsBox = new System.Windows.Forms.GroupBox();
            this.modbusCoilLabel = new System.Windows.Forms.Label();
            this.modbusPortLabel = new System.Windows.Forms.Label();
            this.modbusHostLabel = new System.Windows.Forms.Label();
            this.modbusCoilTextBox = new System.Windows.Forms.TextBox();
            this.modbusPortTextBox = new System.Windows.Forms.TextBox();
            this.modbusHostTextBox = new System.Windows.Forms.TextBox();

            this.powerOnButton = new System.Windows.Forms.Button();
            this.powerOffButton = new System.Windows.Forms.Button();
            this.uploadStagerButton = new System.Windows.Forms.Button();

            this.logTextBox = new System.Windows.Forms.RichTextBox();

            this.plcSettingsBox.SuspendLayout();
            this.modbusSettingsBox.SuspendLayout();
            this.SuspendLayout();

            //
            // plcSettingsBox
            //
            this.plcSettingsBox.Controls.Add(this.plcPortLabel);
            this.plcSettingsBox.Controls.Add(this.plcHostLabel);
            this.plcSettingsBox.Controls.Add(this.plcPortTextBox);
            this.plcSettingsBox.Controls.Add(this.plcHostTextBox);
            this.plcSettingsBox.Location = new System.Drawing.Point(12, 12);
            this.plcSettingsBox.Name = "plcSettingsBox";
            this.plcSettingsBox.Size = new System.Drawing.Size(260, 80);
            this.plcSettingsBox.TabIndex = 0;
            this.plcSettingsBox.TabStop = false;
            this.plcSettingsBox.Text = "PLC Connection (Serial-to-TCP)";
            //
            // plcPortLabel
            //
            this.plcPortLabel.AutoSize = true;
            this.plcPortLabel.Location = new System.Drawing.Point(6, 51);
            this.plcPortLabel.Name = "plcPortLabel";
            this.plcPortLabel.Size = new System.Drawing.Size(35, 15);
            this.plcPortLabel.TabIndex = 3;
            this.plcPortLabel.Text = "Port:";
            //
            // plcHostLabel
            //
            this.plcHostLabel.AutoSize = true;
            this.plcHostLabel.Location = new System.Drawing.Point(6, 22);
            this.plcHostLabel.Name = "plcHostLabel";
            this.plcHostLabel.Size = new System.Drawing.Size(38, 15);
            this.plcHostLabel.TabIndex = 2;
            this.plcHostLabel.Text = "Host:";
            //
            // plcPortTextBox
            //
            this.plcPortTextBox.Location = new System.Drawing.Point(70, 48);
            this.plcPortTextBox.Name = "plcPortTextBox";
            this.plcPortTextBox.Size = new System.Drawing.Size(180, 23);
            this.plcPortTextBox.TabIndex = 1;
            this.plcPortTextBox.Text = "10001";
            //
            // plcHostTextBox
            //
            this.plcHostTextBox.Location = new System.Drawing.Point(70, 19);
            this.plcHostTextBox.Name = "plcHostTextBox";
            this.plcHostTextBox.Size = new System.Drawing.Size(180, 23);
            this.plcHostTextBox.TabIndex = 0;
            this.plcHostTextBox.Text = "localhost";
            //
            // modbusSettingsBox
            //
            this.modbusSettingsBox.Controls.Add(this.modbusCoilLabel);
            this.modbusSettingsBox.Controls.Add(this.modbusPortLabel);
            this.modbusSettingsBox.Controls.Add(this.modbusHostLabel);
            this.modbusSettingsBox.Controls.Add(this.modbusCoilTextBox);
            this.modbusSettingsBox.Controls.Add(this.modbusPortTextBox);
            this.modbusSettingsBox.Controls.Add(this.modbusHostTextBox);
            this.modbusSettingsBox.Location = new System.Drawing.Point(12, 98);
            this.modbusSettingsBox.Name = "modbusSettingsBox";
            this.modbusSettingsBox.Size = new System.Drawing.Size(260, 110);
            this.modbusSettingsBox.TabIndex = 1;
            this.modbusSettingsBox.TabStop = false;
            this.modbusSettingsBox.Text = "Modbus Power Supply";
            //
            // modbusCoilLabel
            //
            this.modbusCoilLabel.AutoSize = true;
            this.modbusCoilLabel.Location = new System.Drawing.Point(6, 80);
            this.modbusCoilLabel.Name = "modbusCoilLabel";
            this.modbusCoilLabel.Size = new System.Drawing.Size(60, 15);
            this.modbusCoilLabel.TabIndex = 5;
            this.modbusCoilLabel.Text = "Coil Addr:";
            //
            // modbusPortLabel
            //
            this.modbusPortLabel.AutoSize = true;
            this.modbusPortLabel.Location = new System.Drawing.Point(6, 51);
            this.modbusPortLabel.Name = "modbusPortLabel";
            this.modbusPortLabel.Size = new System.Drawing.Size(35, 15);
            this.modbusPortLabel.TabIndex = 4;
            this.modbusPortLabel.Text = "Port:";
            //
            // modbusHostLabel
            //
            this.modbusHostLabel.AutoSize = true;
            this.modbusHostLabel.Location = new System.Drawing.Point(6, 22);
            this.modbusHostLabel.Name = "modbusHostLabel";
            this.modbusHostLabel.Size = new System.Drawing.Size(59, 15);
            this.modbusHostLabel.TabIndex = 3;
            this.modbusHostLabel.Text = "IP Address:";
            //
            // modbusCoilTextBox
            //
            this.modbusCoilTextBox.Location = new System.Drawing.Point(70, 77);
            this.modbusCoilTextBox.Name = "modbusCoilTextBox";
            this.modbusCoilTextBox.Size = new System.Drawing.Size(180, 23);
            this.modbusCoilTextBox.TabIndex = 2;
            this.modbusCoilTextBox.Text = "1";
            //
            // modbusPortTextBox
            //
            this.modbusPortTextBox.Location = new System.Drawing.Point(70, 48);
            this.modbusPortTextBox.Name = "modbusPortTextBox";
            this.modbusPortTextBox.Size = new System.Drawing.Size(180, 23);
            this.modbusPortTextBox.TabIndex = 1;
            this.modbusPortTextBox.Text = "502";
            //
            // modbusHostTextBox
            //
            this.modbusHostTextBox.Location = new System.Drawing.Point(70, 19);
            this.modbusHostTextBox.Name = "modbusHostTextBox";
            this.modbusHostTextBox.Size = new System.Drawing.Size(180, 23);
            this.modbusHostTextBox.TabIndex = 0;
            this.modbusHostTextBox.Text = "192.168.1.123";
            //
            // delayLabel
            //
            this.delayLabel = new System.Windows.Forms.Label();
            this.delayLabel.AutoSize = true;
            this.delayLabel.Location = new System.Drawing.Point(6, 110);
            this.delayLabel.Name = "delayLabel";
            this.delayLabel.Size = new System.Drawing.Size(95, 15);
            this.delayLabel.Text = "Power-On Delay (s):";
            //
            // delayNumericUpDown
            //
            this.delayNumericUpDown = new System.Windows.Forms.NumericUpDown();
            this.delayNumericUpDown.Location = new System.Drawing.Point(150, 108);
            this.delayNumericUpDown.Name = "delayNumericUpDown";
            this.delayNumericUpDown.Size = new System.Drawing.Size(100, 23);
            this.delayNumericUpDown.TabIndex = 3;
            this.delayNumericUpDown.Value = new decimal(new int[] { 1, 0, 0, 0 });
            //
            // modbusSettingsBox
            //
            this.modbusSettingsBox.Size = new System.Drawing.Size(260, 140);
            this.modbusSettingsBox.Controls.Add(this.delayLabel);
            this.modbusSettingsBox.Controls.Add(this.delayNumericUpDown);
            //
            // powerOnButton
            //
            this.powerOnButton.Location = new System.Drawing.Point(280, 20);
            this.powerOnButton.Name = "powerOnButton";
            this.powerOnButton.Size = new System.Drawing.Size(130, 30);
            this.powerOnButton.TabIndex = 2;
            this.powerOnButton.Text = "Power ON";
            this.powerOnButton.UseVisualStyleBackColor = true;
            this.powerOnButton.Click += new System.EventHandler(this.powerOnButton_Click);
            //
            // powerOffButton
            //
            this.powerOffButton.Location = new System.Drawing.Point(280, 56);
            this.powerOffButton.Name = "powerOffButton";
            this.powerOffButton.Size = new System.Drawing.Size(130, 30);
            this.powerOffButton.TabIndex = 3;
            this.powerOffButton.Text = "Power OFF";
            this.powerOffButton.UseVisualStyleBackColor = true;
            this.powerOffButton.Click += new System.EventHandler(this.powerOffButton_Click);
            //
            // uploadStagerButton
            //
            this.uploadStagerButton.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.uploadStagerButton.Location = new System.Drawing.Point(280, 130);
            this.uploadStagerButton.Name = "uploadStagerButton";
            this.uploadStagerButton.Size = new System.Drawing.Size(130, 120);
            this.uploadStagerButton.TabIndex = 4;
            this.uploadStagerButton.Text = "Upload Stager";
            this.uploadStagerButton.UseVisualStyleBackColor = true;
            this.uploadStagerButton.Click += new System.EventHandler(this.uploadStagerButton_Click);
            //
            // logTextBox
            //
            this.logTextBox.Location = new System.Drawing.Point(12, 217);
            this.logTextBox.Name = "logTextBox";
            this.logTextBox.Size = new System.Drawing.Size(398, 132);
            this.logTextBox.TabIndex = 5;
            this.logTextBox.Text = "";
            this.logTextBox.ReadOnly = true;
            this.logTextBox.BackColor = System.Drawing.Color.Black;
            this.logTextBox.ForeColor = System.Drawing.Color.Lime;
            this.logTextBox.Font = new System.Drawing.Font("Consolas", 9F);

            //
            // MainForm
            //
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(424, 361);
            this.Controls.Add(this.logTextBox);
            this.Controls.Add(this.uploadStagerButton);
            this.Controls.Add(this.powerOffButton);
            this.Controls.Add(this.powerOnButton);
            this.Controls.Add(this.modbusSettingsBox);
            this.Controls.Add(this.plcSettingsBox);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.Name = "MainForm";
            this.Text = "S7 Bootloader Utility";
            this.plcSettingsBox.ResumeLayout(false);
            this.plcSettingsBox.PerformLayout();
            this.modbusSettingsBox.ResumeLayout(false);
            this.modbusSettingsBox.PerformLayout();
            this.ResumeLayout(false);
        }

        #endregion

        private System.Windows.Forms.GroupBox plcSettingsBox;
        private System.Windows.Forms.Label plcPortLabel;
        private System.Windows.Forms.Label plcHostLabel;
        private System.Windows.Forms.TextBox plcPortTextBox;
        private System.Windows.Forms.TextBox plcHostTextBox;
        private System.Windows.Forms.GroupBox modbusSettingsBox;
        private System.Windows.Forms.Label modbusCoilLabel;
        private System.Windows.Forms.Label modbusPortLabel;
        private System.Windows.Forms.Label modbusHostLabel;
        private System.Windows.Forms.TextBox modbusCoilTextBox;
        private System.Windows.Forms.TextBox modbusPortTextBox;
        private System.Windows.Forms.TextBox modbusHostTextBox;
        private System.Windows.Forms.Button powerOnButton;
        private System.Windows.Forms.Button powerOffButton;
        private System.Windows.Forms.Button uploadStagerButton;
        private System.Windows.Forms.RichTextBox logTextBox;
        private System.Windows.Forms.Label delayLabel;
        private System.Windows.Forms.NumericUpDown delayNumericUpDown;
    }
}
