using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Threading;
using System.Security.Cryptography;
using System.ComponentModel;
using System.Net;
using MiscUtil.Compression.Vcdiff;
using System.Windows.Media;
using UE4_Patcher.Extensions;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.Reflection;
using System.Net.NetworkInformation;

using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace ProcessMonitoring
{
    public sealed class NetworkPerformanceReporter : IDisposable
    {
        private DateTime m_EtwStartTime;
        private TraceEventSession m_EtwSession;

        private readonly Counters m_Counters = new Counters();

        private class Counters
        {
            public long Received;
            public long Sent;
        }

        private NetworkPerformanceReporter() { }

        public static NetworkPerformanceReporter Create()
        {
            var networkPerformancePresenter = new NetworkPerformanceReporter();
            networkPerformancePresenter.Initialise();
            return networkPerformancePresenter;
        }

        private void Initialise()
        {
            // Note that the ETW class blocks processing messages, so should be run on a different thread if you want the application to remain responsive.
            Task.Run(() => StartEtwSession());
        }

        private void StartEtwSession()
        {
            try
            {
                var processId = Process.GetCurrentProcess().Id;
                ResetCounters();

                using (m_EtwSession = new TraceEventSession("MyKernelAndClrEventsSession"))
                {
                    m_EtwSession.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

                    m_EtwSession.Source.Kernel.TcpIpRecv += data =>
                    {
                        if (data.ProcessID == processId)
                        {
                            lock (m_Counters)
                            {
                                m_Counters.Received += data.size;
                            }
                        }
                    };

                    m_EtwSession.Source.Kernel.TcpIpSend += data =>
                    {
                        if (data.ProcessID == processId)
                        {
                            lock (m_Counters)
                            {
                                m_Counters.Sent += data.size;
                            }
                        }
                    };

                    m_EtwSession.Source.Process();
                }
            }
            catch
            {
                ResetCounters(); // Stop reporting figures
                // Probably should log the exception
            }
        }

        public NetworkPerformanceData GetNetworkPerformanceData()
        {
            var timeDifferenceInSeconds = (DateTime.Now - m_EtwStartTime).TotalSeconds;

            NetworkPerformanceData networkData;

            lock (m_Counters)
            {
                networkData = new NetworkPerformanceData
                {
                    BytesReceived = Convert.ToInt64(m_Counters.Received / timeDifferenceInSeconds),
                    BytesSent = Convert.ToInt64(m_Counters.Sent / timeDifferenceInSeconds)
                };

            }

            // Reset the counters to get a fresh reading for next time this is called.
            ResetCounters();

            return networkData;
        }

        private void ResetCounters()
        {
            lock (m_Counters)
            {
                m_Counters.Sent = 0;
                m_Counters.Received = 0;
            }
            m_EtwStartTime = DateTime.Now;
        }

        public void Dispose()
        {
            m_EtwSession?.Dispose();
        }
    }

    public sealed class NetworkPerformanceData
    {
        public long BytesReceived { get; set; }
        public long BytesSent { get; set; }
    }
}

namespace UE4_Patcher
{
    public static class MainClass
    {
        public static void Main(string[] args)
        {
            RequireAdministrator();
        }

        [DllImport("libc")]
        public static extern uint getuid();

        /// <summary>
        /// Asks for administrator privileges upgrade if the platform supports it, otherwise does nothing
        /// </summary>
        public static void RequireAdministrator()
        {
            string name = System.AppDomain.CurrentDomain.FriendlyName;
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                    {
                        WindowsPrincipal principal = new WindowsPrincipal(identity);
                        if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                        {
                            throw new InvalidOperationException($"Application must be run as administrator. Right click the {name} file and select 'run as administrator'.");
                        }
                    }
                }
                else if (getuid() != 0)
                {
                    throw new InvalidOperationException($"Application must be run as root/sudo. From terminal, run the executable as 'sudo {name}'");
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException($"Application must be run as administrator. Right click the {name} file and select 'run as administrator'.", ex);
            }
        }
    }
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string localVersion;
        private string onlineVersion;
        private BackgroundWorker patchWorker = new BackgroundWorker();
        private string BASE_URL = @"http://d37ob46rk09il3.cloudfront.net/BnS_UE4/";
        private string BNS_PATH = "";
        private long currentBytes = 0L;
        private long totalBytes = 0L;
        private List<BnSFileInfo> BnSInfoMap;
        private List<MultipartArchives> BnSMultiParts;
        private static List<string> errorLog;
        System.Windows.Threading.DispatcherTimer dlTimer = new System.Windows.Threading.DispatcherTimer();

        public class BnSFileInfo
        {
            public string path { get; set; }
            public string size { get; set; }
            public string hash { get; set; }
            public string flag { get; set; }
            public bool Downloaded { get; set; }
        }

        public struct PatchFile_FlagType
        {
            public const string Unknown = "0";
            public const string UnChanged = "1";
            public const string Changed = "2";
            public const string ChangedDiff = "3";
            public const string ChangedOriginal = "4";
            public const string Added = "5";
        }


        public class MultipartArchives
        {
            public string File { get; set; }
            public string Directory { get; set; }
            public List<string> Archives { get; set; }
        }
        ProcessMonitoring.NetworkPerformanceReporter Network = null;

        public MainWindow()
        {
            try
            {
                MainClass.RequireAdministrator();
            } catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                Application.Current.Shutdown();
            }

            InitializeComponent();
            this.MouseDown += delegate { try { DragMove(); } catch (Exception) { } };
            patchWorker.DoWork += new DoWorkEventHandler(PatchGameWorker);
            patchWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(PatchGameFinished);
            ServicePointManager.DefaultConnectionLimit = 50; //Raise the concurrent connection limit for WebClient

            dlTimer.Tick += new EventHandler(timer1_Tick);
            dlTimer.Interval = TimeSpan.FromSeconds(1);
        }

        private void DownloadBtn_Click(object sender, RoutedEventArgs e)
        {
            IdleGrid.Visibility = Visibility.Hidden;
            ProgressGrid.Visibility = Visibility.Visible;
            PatchingLabel.Visibility = Visibility.Hidden;
            ErrorLog.Document.Blocks.Clear();

            if ((bool)CustomPatch.IsChecked)
                onlineVersion = CustomPatchBox.Text;
            patchWorker.RunWorkerAsync();
        }

        private void MinimizeApp(object sender, RoutedEventArgs e) => this.WindowState = WindowState.Minimized;
        private void ExitApp(object sender, RoutedEventArgs e) => this.Close();

        private void PatchGameFinished(object sender, RunWorkerCompletedEventArgs e)
        {
            if (errorLog.Count > 0)
            {
                localVersion = onlineVersion;
                WriteError("Running a file check can possibly resolve issues above, try that before pointing it out.");
            }
            else
                WriteError("No issues thrown, game should be good to go.");

            FilesProcessed(0);
            DownloadBtn.IsEnabled = true;
            DownloadBtn.Content = "File Check";
            ProgressGrid.Visibility = Visibility.Hidden;
            localVersionLabel.Content = onlineVersion.ToString();
            LocalGameLbl.Foreground = Brushes.Green;
            IdleGrid.Visibility = Visibility.Visible;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetDiskFreeSpaceEx(string lpDirectoryName,
            out ulong lpFreeBytesAvailable,
            out ulong lpTotalNumberOfBytes,
            out ulong lpTotalNumberOfFreeBytes);

        private long GetDiskSpace(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path)) throw new ArgumentException("invalid path");

                ulong buffer = 0;
                if (!GetDiskFreeSpaceEx(path, out ulong freeSpace, out buffer, out buffer))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                return (long)freeSpace;
            }
            catch (Exception)
            {
                return 0L;
            }
        }

        private void WriteError(string msg) => this.ErrorLog.Dispatcher.BeginInvoke(new Action(() => { ErrorLog.AppendText(msg + "\r"); ErrorLog.ScrollToEnd(); }));

        private void BrowseGameFolder(object sender, RoutedEventArgs e)
        {
            using (var folder = new System.Windows.Forms.FolderBrowserDialog())
            {
                System.Windows.Forms.DialogResult Result = folder.ShowDialog();
                if (Result == System.Windows.Forms.DialogResult.OK && !string.IsNullOrWhiteSpace(folder.SelectedPath))
                {
                    Properties.Settings.Default.GamePath = folder.SelectedPath + "\\";
                    Properties.Settings.Default.Save();
                }
            }

            string versionFile = Directory.GetFiles(Properties.Settings.Default.GamePath, "VersionInfo_*.ini").FirstOrDefault();
            if (string.IsNullOrEmpty(versionFile))
            {
                //For whatever stupid reason the export for WritePrivateProfileString is not working for blank ini files
                //So I have to write this manually...
                using (StreamWriter sw = File.CreateText(Path.Combine(Properties.Settings.Default.GamePath, "VersionInfo_BnS_UE4.ini")))
                {
                    sw.WriteLine("[VersionInfo]");
                    sw.WriteLine("GlobalVersion=0");
                    sw.WriteLine("DownloadIndex=0");
                    sw.WriteLine("LanguagePackage=en-US");
                }
                localVersion = "0";
            }
            else
            {
                IniHandler VersionInfo_BnS = new IniHandler(versionFile);
                localVersion = VersionInfo_BnS.Read("VersionInfo", "GlobalVersion");
            }

            UpdateUI();
        }

        private void UpdateUI()
        {
            updateDiskspace();
            localVersionLabel.Content = localVersion.ToString();
            currentVersionLabel.Content = String.Format("{0}", (onlineVersion == "") ? "Error" : onlineVersion);

            //Redundant..? Doing it cause fuck it.
            if (onlineVersion == "")
            {
                OnlineGameLbl.Foreground = Brushes.Red;
                onlineVersion = localVersion;
            }
            else
                OnlineGameLbl.Foreground = Brushes.Green;

            if (onlineVersion != localVersion)
                LocalGameLbl.Foreground = Brushes.Red;
            else
            {
                LocalGameLbl.Foreground = Brushes.Green;
                DownloadBtn.Content = "File Check";
            }

            if (localVersion == "0")
                DownloadBtn.Content = "Install";
        }

        private void updateDiskspace() =>
            diskSpaceBlock.Dispatcher.BeginInvoke(new Action(() => { diskSpaceBlock.Text = string.Format("Free Space: {0} | Required: 65GB", SizeSuffix(GetDiskSpace(Properties.Settings.Default.GamePath), 2)); }));

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            WriteError("All errors will be logged here. If any errors occur please for the love of god try running a file check first before going 'it don't work i got this error'. 99% of the time a file check will be the solution to your problem.\r\rAny issues related to running out of memory just means download more ram, but seriously just run a file check and try lowering the updater threads.");
            if (!string.IsNullOrEmpty(Properties.Settings.Default.GamePath)) goto MainInit;

        Prompt:
            MessageBox.Show("Select a folder to install Blade & Soul UE4", "No Game Path Detected");
            BrowseGameFolder(sender, e);

        MainInit:
            if (!Directory.Exists(Properties.Settings.Default.GamePath)) goto Prompt;
            string versionFile = Directory.GetFiles(Properties.Settings.Default.GamePath, "VersionInfo_*.ini").FirstOrDefault();
            if (string.IsNullOrEmpty(versionFile))
            {
                //For whatever stupid reason the export for WritePrivateProfileString is not working for blank ini files
                //So I have to write this manually...
                using (StreamWriter sw = File.CreateText(Path.Combine(Properties.Settings.Default.GamePath, string.Format("VersionInfo_{0}.ini", loginServerVar))))
                {
                    sw.WriteLine("[VersionInfo]");
                    sw.WriteLine("GlobalVersion=0");
                    sw.WriteLine("DownloadIndex=0");
                    sw.WriteLine("LanguagePackage=en-US");
                }
                localVersion = "0";
            }
            else
            {
                IniHandler VersionInfo_BnS = new IniHandler(versionFile);
                localVersion = VersionInfo_BnS.Read("VersionInfo", "GlobalVersion");
            }

            lstBoxUpdaterThreads.SelectedIndex = Properties.Settings.Default.ThreadCount;
            lstBox_region.SelectedIndex = Properties.Settings.Default.Region;

            BASE_URL = @"http://d37ob46rk09il3.cloudfront.net/BnS_UE4/";

            onlineVersion = onlineVersionNumber();
            //onlineVersion = string.Format("{0}", int.Parse(onlineVersion) - 2);

            UpdateUI();
        }

        private bool DeltaPatch(string original, string patch)
        {
            string targetFileName = Path.GetFileName(original);

            try
            {
                using (FileStream originalFile = File.OpenRead(original))
                using (FileStream patchFile = File.OpenRead(patch))
                using (FileStream targetFile = File.Open(Path.Combine(Path.GetDirectoryName(patch), targetFileName), FileMode.OpenOrCreate, FileAccess.ReadWrite))
                    VcdiffDecoder.Decode(originalFile, patchFile, targetFile);

                return true;
            }
            catch (Exception ex)
            {
                errorLog.Add(string.Format("{0} Failed to delta - {1}", Path.GetFileName(patch), ex.Message));
                return false;
            }
            finally
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        private static bool RemoteFileExists(string url)
        {
            bool result;
            HttpWebRequest httpWebRequest;
            HttpWebResponse httpWebResponse = null;
            try
            {
                httpWebRequest = WebRequest.Create(url) as HttpWebRequest;
                httpWebRequest.Method = "HEAD";
                httpWebResponse = httpWebRequest.GetResponse() as HttpWebResponse;
                result = httpWebResponse.StatusCode == HttpStatusCode.OK;
            }
            catch
            {
                result = false;
            }
            finally
            {
                if (httpWebResponse != null)
                {
                    httpWebResponse.Close();
                    httpWebResponse.Dispose();
                }
            }
            return result;
        }

        /// <summary>
        /// 7zip LZMA Extraction
        /// Assumes it is single file and not an archive
        /// </summary>
        /// <param name="inFile">Source file</param>
        /// <param name="outFile">Target file</param>
        /// <param name="cleanup">Delete source file? True by default</param>
        /// <exception cref="Exception"></exception>
        public static void DecompressFileLZMA(string inFile, string outFile, bool cleanup = true)
        {
            if (File.Exists(outFile))
                File.Delete(outFile);

            using (FileStream input = new FileStream(inFile, FileMode.Open))
            using (FileStream output = new FileStream(outFile, FileMode.Create))
            {
                SevenZip.Compression.LZMA.Decoder decoder = new SevenZip.Compression.LZMA.Decoder();

                byte[] properties = new byte[5];
                if (input.Read(properties, 0, 5) != 5)
                    throw new Exception("input .lzma is too short");
                decoder.SetDecoderProperties(properties);

                byte[] sizeBytes = new byte[8];
                if (input.Read(sizeBytes, 0, 8) != 8)
                    throw new Exception("input .lzma is too short");

                long outSize = BitConverter.ToInt64(sizeBytes, 0);
                long compressedSize = input.Length - input.Position;
                decoder.Code(input, output, compressedSize, outSize, null);
            }

            if (cleanup)
                File.Delete(inFile);
        }

        public static bool IsFileLocked(string file)
        {
            try
            {
                using (var stream = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.None))
                    stream.Close();
            }
            catch (IOException)
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// 7zip LZMA Stream Extraction
        /// Same as DecompressFileLZMA but with split parts being merged into a single stream
        /// Still assuming it is a single file and not an archive
        /// </summary>
        /// <param name="directory">Directory of parted files</param>
        /// <param name="files">File list part files we're merging, requires it to be alphabetically sorted first</param>
        /// <param name="outFile">Target file</param>
        /// <param name="cleanup">Delete split parts? True by default</param>
        /// <returns>Empty string if no errors</returns>
        public static string DecompressStreamLZMA(string directory, List<string> files, string outFile, bool cleanup = true)
        {
            string status = string.Empty;
            string fullOutFile = Path.Combine(directory, outFile);
            if (File.Exists(fullOutFile))
                File.Delete(fullOutFile);

            try
            {
                //new FileStream(fullOutFile, FileMode.Create, FileAccess.Write)
                using (var output = new FileStream(fullOutFile, FileMode.Create))
                using (var input = new ConcatStream(files.Select(file => File.OpenRead(Path.Combine(directory, file)))))
                {
                    var decoder = new SevenZip.Compression.LZMA.Decoder();

                    byte[] properties = new byte[5];
                    if (input.Read(properties, 0, 5) != 5)
                        throw (new Exception("input .lzma is too short"));
                    decoder.SetDecoderProperties(properties);

                    byte[] sizeBytes = new byte[8];
                    if (input.Read(sizeBytes, 0, 8) != 8)
                        throw (new Exception("input .lzma is too short"));

                    long outSize = BitConverter.ToInt64(sizeBytes, 0);
                    long compressedSize = input.Length - 13;
                    decoder.Code(input, output, compressedSize, outSize, null);
                }

                // only delete files if successful
                if (cleanup)
                    files.ForEach(f => File.Delete(Path.Combine(directory, f)));
            }
            catch (Exception ex)
            {
                //Logger.log.Error("Functions::Extraction::DecompressStreamLZMA\nType: {0}\n{1}\n{2}", ex.GetType().Name, ex.ToString(), ex.StackTrace);
                status = string.Format("Failed to create {0}, Data Error due to missing parts", outFile);
            }

            return status;
        }

        private void FilesProcessed(int value)
        {
            Duration duration = new Duration(TimeSpan.FromSeconds(1));

            currentProgress.Dispatcher.BeginInvoke(new Action(() =>
            {
                System.Windows.Media.Animation.DoubleAnimation da = new System.Windows.Media.Animation.DoubleAnimation(value, duration);
                currentProgress.BeginAnimation(ProgressBar.ValueProperty, da);
            }));
        }

        public static string SHA1HASH(string filePath)
        {
            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open))
                using (BufferedStream bs = new BufferedStream(fs))
                {
                    using (SHA1Managed sha1 = new SHA1Managed())
                    {
                        byte[] hash = sha1.ComputeHash(bs);
                        StringBuilder formatted = new StringBuilder(2 * hash.Length);
                        foreach (byte b in hash)
                        {
                            formatted.AppendFormat("{0:x2}", b);
                        }
                        return formatted.ToString();
                    }
                }
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        private static bool HasFlags(string input, List<string> flags)
        {
            foreach (var flag in flags)
                if (input.EndsWith(flag))
                    return true;
            return false;
        }
        private bool DownloadContents(string url, string path, bool retry = true)
        {
            if (!Directory.Exists(Path.GetDirectoryName(path)))
                Directory.CreateDirectory(Path.GetDirectoryName(path));

            int retries = 0;
            while (true)
            {
                using (var client = new WebClient { Proxy = null })
                {
                    try
                    {
                        client.DownloadFile(new Uri(url), path);
                        return true;
                    }
                    catch (WebException ex)
                    {
                        Debug.WriteLine(url);
                        Debug.WriteLine("{0} Retries", retries);
                        if (!retry || retries >= 6) return false;
                        retries++;
                    }
                }
            }
        }

        static readonly string[] SizeSuffixes =
                   { "bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" };
        static string SizeSuffix(Int64 value, int decimalPlaces = 1, bool showSuffix = true)
        {
            if (decimalPlaces < 0) { throw new ArgumentOutOfRangeException("decimalPlaces"); }
            if (value < 0) { return "-" + SizeSuffix(-value); }
            if (value == 0) { return string.Format("{0:n" + decimalPlaces + "}{1}", 0, showSuffix ? " bytes" : ""); }

            // mag is 0 for bytes, 1 for KB, 2, for MB, etc.
            int mag = (int)Math.Log(value, 1024);

            // 1L << (mag * 10) == 2 ^ (10 * mag) 
            // [i.e. the number of bytes in the unit corresponding to mag]
            decimal adjustedSize = (decimal)value / (1L << (mag * 10));

            // make adjustment when the value is large enough that
            // it would round up to 1000 or more
            if (Math.Round(adjustedSize, decimalPlaces) >= 1000)
            {
                mag += 1;
                adjustedSize /= 1024;
            }

            return string.Format("{0:n" + decimalPlaces + "} {1}",
                adjustedSize,
                (showSuffix) ? SizeSuffixes[mag] : "");
        }

        private void PatchGameWorker(object sender, DoWorkEventArgs e)
        {
            try
            {
                BNS_PATH = Path.GetFullPath(Properties.Settings.Default.GamePath);
                string FileInfoName = string.Format("FileInfoMap_{0}.dat", loginServerVar);
                string PatchInfoName = string.Format("PatchFileInfo_{0}.dat", loginServerVar);
                string targetVersion = "0";

            StartPatchThread:
                if (localVersion != "0")
                {
                    if (int.Parse(onlineVersion) - int.Parse(localVersion) > 1)
                        targetVersion = (int.Parse(localVersion) + 1).ToString();
                    else
                        targetVersion = onlineVersion;
                }
                else
                    targetVersion = onlineVersion;

                string FileInfoURL = String.Format(@"{0}{1}/Patch/{2}_{1}.dat.zip", BASE_URL, targetVersion, Path.GetFileNameWithoutExtension(FileInfoName));
                string PatchInfoURL = String.Format(@"{0}{1}/Patch/{2}_{1}.dat.zip", BASE_URL, targetVersion, Path.GetFileNameWithoutExtension(PatchInfoName));

                totalBytes = 0L;
                currentBytes = 0L;

                BnSInfoMap = new List<BnSFileInfo>();
                BnSMultiParts = new List<MultipartArchives>();
                var partArchives = new List<MultipartArchives>();
                errorLog = new List<string>();

                bool deltaPatch = localVersion != "0" && int.Parse(targetVersion) > int.Parse(localVersion);
                string PatchDirectory = Path.Combine(BNS_PATH, "PatchManager", targetVersion);

                DltPLbl.Dispatcher.BeginInvoke(new Action(() => { DltPLbl.Visibility = (deltaPatch) ? Visibility.Visible : Visibility.Hidden; }));

                if (!RemoteFileExists(PatchInfoURL))
                    throw new Exception(String.Format("PatchFileInfo for build #{0} could not be reached", onlineVersion));

                if (!Directory.Exists(PatchDirectory))
                    Directory.CreateDirectory(PatchDirectory);

                Dispatchers.textBlock(ProgressBlock, "Retrieving " + PatchInfoName);
                if (!DownloadContents(PatchInfoURL, Path.Combine(PatchDirectory, PatchInfoName + ".zip"), false))
                    throw new Exception("Failed to download " + PatchInfoName);

                Dispatchers.textBlock(ProgressBlock, "Retrieving " + FileInfoName);
                if (!DownloadContents(FileInfoURL, Path.Combine(PatchDirectory, FileInfoName + ".zip"), false))
                    throw new Exception("Failed to download " + FileInfoName);

                Dispatchers.textBlock(ProgressBlock, "Decompressing File Maps");
                DecompressFileLZMA(Path.Combine(PatchDirectory, FileInfoName + ".zip"), Path.Combine(PatchDirectory, FileInfoName));
                DecompressFileLZMA(Path.Combine(PatchDirectory, PatchInfoName + ".zip"), Path.Combine(PatchDirectory, PatchInfoName));

                // Fix for new installations and possibly another unknown bug?
                if (!File.Exists(Path.Combine(BNS_PATH, FileInfoName)))
                    File.Copy(Path.Combine(PatchDirectory, FileInfoName), Path.Combine(BNS_PATH, FileInfoName));

                List<string> OnlineFileInfoMap = File.ReadLines(Path.Combine(PatchDirectory, FileInfoName)).ToList<string>();
                List<string> PatchInfoMap = File.ReadLines(Path.Combine(PatchDirectory, PatchInfoName)).ToList<string>();
                List<string> CurrentFileInfoMap = File.ReadLines(Path.Combine(BNS_PATH, FileInfoName)).ToList<string>();

                int totalFiles = OnlineFileInfoMap.Count();
                int processedFiles = 0;
                int threadCount = Properties.Settings.Default.ThreadCount + 1;

                Dispatchers.labelContent(PatchingLabel, "Scanning");

                Parallel.ForEach<string>(OnlineFileInfoMap, new ParallelOptions { MaxDegreeOfParallelism = threadCount }, delegate (string line)
                {
                    string[] lineData = line.Split(new char[] { ':' });
                    string FilePath = lineData[0];
                    string FileSize = lineData[1];
                    string FileHash = lineData[2];
                    string FileFlag = lineData[3];

                    FileInfo fileInfo = new FileInfo(Path.Combine(BNS_PATH, FilePath));
                    string fHash = fileInfo.Exists ? SHA1HASH(fileInfo.FullName) : "";
                    if (deltaPatch)
                    {
                        if (fileInfo.Exists && fHash == FileHash) goto FileInfoEnd;
                        // Make sure the hash matches current fileInfoMap hash, if not trigger full download
                        var oldF = CurrentFileInfoMap.FirstOrDefault(x => x.Split(new char[] { ':' })[0] == FilePath);

                        if (fileInfo.Exists && oldF != null && fHash != oldF.Split(new char[] { ':' })[2])
                        {
                            foreach (var file in PatchInfoMap.Where(f => f.Contains(FilePath) && f.DatFilePathMatches(FilePath) && (f.EndsWith(PatchFile_FlagType.Added)
                                || f.EndsWith(PatchFile_FlagType.ChangedOriginal)
                                || f.EndsWith(PatchFile_FlagType.UnChanged)))
                            )
                            {
                                string[] lData = file.Split(new char[] { ':' });
                                BnSInfoMap.Add(new BnSFileInfo { path = lData[0], size = lData[1], hash = lData[2], flag = lData[3], Downloaded = false });
                                Interlocked.Add(ref totalBytes, long.Parse(lData[1]));
                            }
                        }
                        else
                        {
                            List<string> flags;
                            if (fileInfo.Exists)
                                flags = new List<string> { PatchFile_FlagType.ChangedDiff, PatchFile_FlagType.Added };
                            else
                                flags = new List<string> { PatchFile_FlagType.Added, PatchFile_FlagType.ChangedOriginal, PatchFile_FlagType.UnChanged };

                            foreach (var file in PatchInfoMap.Where(f => f.Contains(FilePath) && f.DatFilePathMatches(FilePath) &&
                            HasFlags(f, flags)))
                            {
                                string[] lData = file.Split(new char[] { ':' });
                                BnSInfoMap.Add(new BnSFileInfo { path = lData[0], size = lData[1], hash = lData[2], flag = lData[3], Downloaded = false });
                                Interlocked.Add(ref totalBytes, long.Parse(lData[1]));
                            }
                        }
                    }
                    else
                    {
                        if (fileInfo.Exists && fHash == FileHash) goto FileInfoEnd;

                        foreach (var file in PatchInfoMap.Where(f => f.Contains(FilePath) && f.DatFilePathMatches(FilePath) && (f.EndsWith(PatchFile_FlagType.Added)
                                || f.EndsWith(PatchFile_FlagType.ChangedOriginal)
                                || f.EndsWith(PatchFile_FlagType.UnChanged)))
                            )
                        {
                            string[] lData = file.Split(new char[] { ':' });
                            BnSInfoMap.Add(new BnSFileInfo { path = lData[0], size = lData[1], hash = lData[2], flag = lData[3], Downloaded = false });
                            Interlocked.Add(ref totalBytes, long.Parse(lData[1]));
                        }
                    }

                FileInfoEnd:
                    Interlocked.Increment(ref processedFiles);
                    FilesProcessed((int)((double)processedFiles / totalFiles * 100));
                    Dispatchers.textBlock(ProgressBlock, String.Format("{0} / {1} files scanned", processedFiles, totalFiles));
                });

                Dispatchers.textBlock(ProgressBlock, String.Format("Download Size: {0} ({1}) files", SizeSuffix(totalBytes, 2), BnSInfoMap.Count()));
                totalFiles = BnSInfoMap.Count();
                if (totalFiles <= 0) goto Cleanup;

                processedFiles = 0;
                PatchingLabel.Dispatcher.BeginInvoke(new Action(() => { PatchingLabel.Visibility = Visibility.Visible; }));

                FilesProcessed(0);
                Dispatchers.labelContent(PatchingLabel, "Downloading...");
                Thread.Sleep(2000); //Create slack for progress bar to reset
                Network = ProcessMonitoring.NetworkPerformanceReporter.Create();
                dlTimer.IsEnabled = true;
                dlTimer.Start();
                // Adding an extra thread on download just cause the download server limits speeds on each file so we'll get more bang for our buck by increasing download tasks
                Parallel.ForEach<BnSFileInfo>(BnSInfoMap, new ParallelOptions { MaxDegreeOfParallelism = threadCount + 1 }, delegate (BnSFileInfo file)
                {
                    if (file == null)
                        return;

                    if (!Directory.Exists(Path.Combine(PatchDirectory, Path.GetDirectoryName(file.path))))
                        Directory.CreateDirectory(Path.Combine(PatchDirectory, Path.GetDirectoryName(file.path)));
                    try
                    {
                        // Check if the file exists
                        if (File.Exists(Path.Combine(PatchDirectory, file.path)))
                        {
                            if (SHA1HASH(Path.Combine(PatchDirectory, file.path)) == file.hash) goto FileDownloadComplete;
                            File.Delete(Path.Combine(PatchDirectory, file.path));
                        }
                    StartDownload:

                        // Downloads the file and validates it matches.
                        if (!DownloadContents(String.Format(@"{0}{1}/Patch/{2}", BASE_URL, targetVersion, file.path.Replace('\\', '/')), Path.Combine(PatchDirectory, file.path)))
                        {
                            errorLog.Add(string.Format("{0} failed to download, max retries also failed.", file.path));
                            goto EndOfThread;
                        }
                        else
                        {
                            // I hate doing this because calculating a SHA1 hash is very expensive
                            if (file.hash != SHA1HASH(Path.Combine(PatchDirectory, file.path)))
                                goto StartDownload;
                        }

                    FileDownloadComplete:
                        file.Downloaded = true;
                        Interlocked.Increment(ref processedFiles);
                        Interlocked.Add(ref currentBytes, long.Parse(file.size));

                        if (!file.path.EndsWith("zip"))
                        {
                            string FileName = Path.GetFileNameWithoutExtension(file.path);
                            int curIndex = partArchives.FindIndex(x => x.File == FileName);
                            try
                            {
                                if (curIndex == -1)
                                    partArchives.Add(new MultipartArchives() { File = FileName, Directory = Path.GetDirectoryName(file.path), Archives = new List<string>() { Path.GetFileName(file.path) } });
                                else
                                    partArchives[curIndex].Archives.Add(Path.GetFileName(file.path));

                            }
                            catch (Exception)
                            {
                                // Logging this is pointless, Parallel code will often trigger this and I don't know of any work around
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        errorLog.Add(ex.Message);
                        //Logger.log.Error("GameUpdater: {0}", ex.Message);
                    }

                EndOfThread:
                    Dispatchers.labelContent(PatchingLabel, String.Format("{0} / {1}", SizeSuffix(currentBytes, 2), SizeSuffix(totalBytes, 2)));
                    FilesProcessed((int)((double)processedFiles / totalFiles * 100));
                });
                dlTimer.Stop();
                Network.Dispose();
                Thread.Sleep(2000);
                if (partArchives.Count <= 0) goto PatchNormalFiles;

                FilesProcessed(0);
                Dispatchers.labelContent(PatchingLabel, "Patching Multi");
                Thread.Sleep(2000); //Create some slack for our progress bar to reset fully (visual).
                var totalFilesM = partArchives.Count();
                processedFiles = 0;

                /*
                    Handles multi-parted archives, KR has been splitting files into multiple archives greater than 20MB
                    but it was never a thing in NA/EU. This process is quite tasking and will take a large majority of time.
                    We'll read all the files and concat the file streams together and then run it through the LZMA decoder
                    to get our full file that is uncompressed.
                 */
                Parallel.ForEach<MultipartArchives>(partArchives, new ParallelOptions { MaxDegreeOfParallelism = threadCount }, delegate (MultipartArchives archive)
                {
                    archive.Archives.Sort(); //We need to sort the list so that each file is loaded in the proper order
                    try
                    {
                        // Start from the index of \ + 1 to get the path to the file we'll be patching.
                        // Path can either start with patchnumber\ or Zip\ and we need to read the path after that
                        string destination = Path.GetFullPath(Path.Combine(BNS_PATH, archive.Directory.Substring(archive.Directory.IndexOf("\\") + 1)));
                        var result = DecompressStreamLZMA(Path.Combine(PatchDirectory, archive.Directory), archive.Archives, archive.File); //Merge the split-archives and run through LZMA decoder

                        if (!result.IsNullOrEmpty())
                            throw new IOException(result);

                        if (File.Exists(Path.Combine(destination, archive.File)))
                            File.Delete(Path.Combine(destination, archive.File));

                        if (!Directory.Exists(destination))
                            Directory.CreateDirectory(destination);

                        if (deltaPatch && archive.File.EndsWith("dlt"))
                        {
                            //Logger.log.Info("Multi File");
                            if (DeltaPatch(Path.Combine(destination, Path.GetFileNameWithoutExtension(archive.File)), Path.Combine(PatchDirectory, archive.Directory, archive.File)))
                            {
                                File.Delete(Path.Combine(PatchDirectory, archive.Directory, archive.File));

                                if (File.Exists(Path.Combine(destination, Path.GetFileNameWithoutExtension(archive.File))))
                                    File.Delete(Path.Combine(destination, Path.GetFileNameWithoutExtension(archive.File)));

                                File.Move(Path.Combine(PatchDirectory, archive.Directory, Path.GetFileNameWithoutExtension(archive.File)), Path.Combine(destination, Path.GetFileNameWithoutExtension(archive.File)));
                            }
                            else
                                throw new Exception(string.Format("{0} failed to delta patch", archive.File));
                        }
                        else
                            File.Move(Path.Combine(PatchDirectory, archive.Directory, archive.File), Path.Combine(destination, archive.File));
                    }
                    catch (Exception ex)
                    {
                        //Logger.log.Error("{0}\n{1}", ex.Message, ex.StackTrace);
                        errorLog.Add(ex.Message);
                    }
                    finally
                    {
                        Interlocked.Increment(ref processedFiles);
                        FilesProcessed((int)((double)processedFiles / totalFilesM * 100));
                    }
                });

            PatchNormalFiles:
                Thread.Sleep(2000);
                FilesProcessed(0);
                processedFiles = 0;
                Dispatchers.labelContent(PatchingLabel, "Patching");
                Thread.Sleep(1000);

                /*
                    Old style patching process, decompress the archive with LZMA decoder
                    if file is a dlt (Delta) file then patch the current file then move it
                    to where it needs to be and cleanup.
                */
                Parallel.ForEach<BnSFileInfo>(BnSInfoMap, new ParallelOptions { MaxDegreeOfParallelism = threadCount }, delegate (BnSFileInfo file)
                {
                    if (file == null)
                        return;

                    if (!file.path.EndsWith("zip"))
                    {
                        Interlocked.Increment(ref processedFiles);
                        FilesProcessed((int)((double)processedFiles / totalFiles * 100));
                        Dispatchers.textBlock(ProgressBlock, String.Format("{0} ({1}%)", SizeSuffix(totalBytes, 2), (int)((double)processedFiles / totalFiles * 100)));
                        return;
                    }

                    // Start from the index of \ + 1 to get the path to the file we'll be patching.
                    string destination = Path.GetFullPath(Path.GetDirectoryName(Path.Combine(BNS_PATH, file.path.Substring(file.path.IndexOf("\\") + 1))));
                    string directory = Path.GetDirectoryName(file.path);
                    string fileName = Path.GetFileNameWithoutExtension(file.path);

                    if (!Directory.Exists(destination))
                        Directory.CreateDirectory(destination);

                    try
                    {
                        DecompressFileLZMA(Path.Combine(PatchDirectory, directory, Path.GetFileName(file.path)), Path.Combine(PatchDirectory, directory, fileName));

                        //Delta Patch
                        if (deltaPatch && file.flag == PatchFile_FlagType.ChangedDiff && Path.GetFileName(file.path).Contains(".dlt"))
                        {
                            if (DeltaPatch(Path.Combine(destination, Path.GetFileNameWithoutExtension(fileName)), Path.Combine(PatchDirectory, directory, fileName)))
                            {
                                File.Delete(Path.Combine(PatchDirectory, directory, fileName));

                                if (File.Exists(Path.Combine(destination, Path.GetFileNameWithoutExtension(fileName))))
                                    File.Delete(Path.Combine(destination, Path.GetFileNameWithoutExtension(fileName)));

                                File.Move(Path.Combine(PatchDirectory, directory, Path.GetFileNameWithoutExtension(fileName)), Path.Combine(destination, Path.GetFileNameWithoutExtension(fileName)));
                            }
                        }
                        else
                        {
                            if (File.Exists(Path.Combine(destination, fileName)))
                                File.Delete(Path.Combine(destination, fileName));

                            File.Move(Path.Combine(PatchDirectory, directory, fileName), Path.Combine(destination, fileName));
                        }

                        Interlocked.Increment(ref processedFiles);
                        FilesProcessed((int)((double)processedFiles / totalFiles * 100));
                        Dispatchers.textBlock(ProgressBlock, String.Format("{0} ({1}%)", SizeSuffix(totalBytes, 2), (int)((double)processedFiles / totalFiles * 100)));
                    }
                    catch (Exception ex)
                    {
                        errorLog.Add(ex.Message);
                        //Logger.log.Error("{0}\n{1}", ex.Message, ex.StackTrace);
                    }
                });

            Cleanup:
                Dispatchers.textBlock(ProgressBlock, "Internal Check");
                if (totalFiles > 0 && BnSInfoMap.Any(x => !x.Downloaded))
                    errorLog.Add("Download checks failed");

                Thread.Sleep(500);
                Dispatchers.textBlock(ProgressBlock, "Cleaning up");

                // Only delete working patch directory and change versionNumber over if successful.
                if (errorLog.Count == 0)
                {
                    if (File.Exists(Path.Combine(BNS_PATH, FileInfoName)))
                        File.Delete(Path.Combine(BNS_PATH, FileInfoName));

                    Dispatchers.labelContent(localVersionLabel, targetVersion);

                    File.Move(Path.Combine(PatchDirectory, FileInfoName), Path.Combine(BNS_PATH, FileInfoName));
                    IniHandler hIni = new IniHandler(Directory.GetFiles(BNS_PATH, "VersionInfo_*.ini").FirstOrDefault());
                    hIni.Write("VersionInfo", "GlobalVersion", targetVersion);
                    localVersion = targetVersion;
                    Directory.Delete(PatchDirectory, true);
                    if (targetVersion != onlineVersion)
                        goto StartPatchThread; // Loop back around to do yet another delta patch
                }
                else
                    goto StartPatchThread;

                Thread.Sleep(3000);
            }
            catch (Exception ex)
            {
                errorLog.Add(ex.Message);
            }

            errorLog.ForEach(er => WriteError(er));

            // Force .NET garbage collection
            GC.Collect();
            GC.WaitForPendingFinalizers();
            onlineVersion = onlineVersionNumber();
        }

        private void timer1_Tick(object sender, EventArgs e) =>
            Dispatchers.textBlock(ProgressBlock, string.Format("Download Speed: {0}/s ", SizeSuffix(Network.GetNetworkPerformanceData().BytesReceived, 2)));

        private void lstBoxUpdaterThreads_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            Properties.Settings.Default.ThreadCount = ((ComboBox)sender).SelectedIndex;
            Properties.Settings.Default.Save();
        }
        
        private static string loginServer;
        private static string loginServerVar;

        private void refreshServerVar()
        {
            switch(Properties.Settings.Default.Region)
            {
                case 1:
                    loginServer = "up4svr.plaync.com.tw";
                    loginServerVar = "TWBNSUE4";
                    BASE_URL = @"http://mmorepo.cdn.plaync.com.tw/TWBNSUE4/";
                    break;
                case 2:
                    loginServer = "up4svr.ncupdate.com";
                    loginServerVar = "BNS_LIVE";
                    BASE_URL = @"http://bnskor.ncupdate.com/BNS_LIVE/";
                    break;
                case 3:
                    loginServer = "up4svr.ncupdate.com"; // I think this is right for the test server
                    loginServerVar = "BNS_TEST";
                    BASE_URL = @"http://bnskortest.ncupdate.com/BNS_TEST/";
                    break;
                default:
                    loginServer = "updater.nclauncher.ncsoft.com";
                    loginServerVar = "BnS_UE4";
                    BASE_URL = @"http://d37ob46rk09il3.cloudfront.net/BnS_UE4/";
                    break;
            }
        }

        public string onlineVersionNumber()
        {
            int version = 0;
            try
            {
                refreshServerVar();
                MemoryStream ms = new MemoryStream();
                BinaryWriter bw = new BinaryWriter(ms);
                NetworkStream ns = new TcpClient(loginServer, 27500).GetStream();

                bw.Write((short)0);
                bw.Write((short)6);
                bw.Write((byte)10);
                bw.Write((byte)loginServerVar.Length);
                bw.Write(Encoding.ASCII.GetBytes(loginServerVar));
                bw.BaseStream.Position = 0L;
                bw.Write((short)ms.Length);

                ns.Write(ms.ToArray(), 0, (int)ms.Length);
                bw.Dispose();
                ms.Dispose();

                ms = new MemoryStream();
                BinaryReader br = new BinaryReader(ms);

                byte[] byte_array = new byte[1024];
                int num = 0;

                do
                {
                    num = ns.Read(byte_array, 0, byte_array.Length);
                    if (num > 0)
                        ms.Write(byte_array, 0, num);
                } while (num == byte_array.Length);

                ms.Position = 9L;
                br.ReadBytes(br.ReadByte() + 5);
                version = br.ReadByte();
                if (br.ReadInt16() != 40)
                {
                    ms.Position -= 2;
                    version += 128 * (br.ReadByte() - 1);
                }
            }
            catch (Exception ex)
            {
                return "";
            }
            return version.ToString();
        }

        private void Region_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            Properties.Settings.Default.Region = ((ComboBox)sender).SelectedIndex;
            Properties.Settings.Default.Save();

            refreshServerVar();

#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            string versionFile = Directory.GetFiles(Properties.Settings.Default.GamePath, "VersionInfo_*.ini").FirstOrDefault();
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.
            if (string.IsNullOrEmpty(versionFile))
            {
                //For whatever stupid reason the export for WritePrivateProfileString is not working for blank ini files
                //So I have to write this manually...
                using (StreamWriter sw = File.CreateText(Path.Combine(Properties.Settings.Default.GamePath, string.Format("VersionInfo_{0}.ini", loginServerVar))))
                {
                    sw.WriteLine("[VersionInfo]");
                    sw.WriteLine("GlobalVersion=0");
                    sw.WriteLine("DownloadIndex=0");
                    sw.WriteLine("LanguagePackage=en-US");
                }
                localVersion = "0";
            }
            else
            {
                IniHandler VersionInfo_BnS = new IniHandler(versionFile);
                localVersion = VersionInfo_BnS.Read("VersionInfo", "GlobalVersion");
            }

            onlineVersion = onlineVersionNumber();
            UpdateUI();
        }
    }
}
