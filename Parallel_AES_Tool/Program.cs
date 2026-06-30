// ============================================================================
//  Program.cs  -  Application entry point.
//
//  Standard Windows Forms bootstrap: it does nothing but configure WinForms
//  and open MainForm. All real work lives in MainForm.cs (UI) and
//  AesCrypto.cs (the parallel AES-CTR engine).
// ============================================================================

using System;
using System.Windows.Forms;

namespace Parallel_AES_Tool
{
    internal static class Program
    {
        // [STAThread] = single-threaded apartment, required by the Windows Forms
        // UI thread (clipboard, dialogs and some COM controls depend on it).
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();                       // use modern themed controls
            Application.SetCompatibleTextRenderingDefault(false);  // use GDI+ text rendering
            Application.Run(new MainForm());                       // open the window and start the message loop
        }
    }
}
