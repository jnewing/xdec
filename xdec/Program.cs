using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using NDesk.Options;
using System.Text.RegularExpressions;

using System.Drawing;
using Console = Colorful.Console;
using Colorful;

namespace xdec
{
    class Program
    {
        static StyleSheet styleSheet = new StyleSheet(Color.White);
        /// <summary>
        /// Entry point.
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            // setup vars
            bool show_help = false;
            string path = null;
            string sid = null;
       
            var p = new OptionSet() {
                { "s|sid=", "SID windows security identifier (whoami /user)",
                    v => sid = v },
                { "p|path=", "path to Xshell sessions folder.",
                    v => path = v },
                { "h|help",  "show this message and exit",
                    v => show_help = v != null },
            };

            // clear console and setup stylesheets, i gots to look swag!
            Console.Clear();
            Console.SetWindowSize(120, 25);
            Console.Title = "xDecrypt - synmuffin";
            Console.BackgroundColor = Color.Black;
            Console.ForegroundColor = Color.White;
            styleSheet.AddStyle("Xshell", Color.Tomato);
            styleSheet.AddStyle("Error", Color.Red);

            // display our header
            ShowHeader();

            List<string> extra = new List<string>();
            try
            {
                extra = p.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("xdec: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try `xdec --help' for more information.");
                exit();
            }

            // if we are dispaying help we do so here and end. 
            if (show_help || string.IsNullOrEmpty(sid))
            {
                ShowHelp(p);
                exit();
            }

            try
            {
                // at this point we can only take one agument or - 
                // we are given a path to the Xshell session folder.
                if (!string.IsNullOrEmpty(path))
                {
                    if (!Directory.Exists(path))
                    {
                        Console.WriteLine("ERROR: Unable to find {0}.", path);
                        exit();
                    }

                    foreach (string file in Directory.GetFiles(path, "*.xsh", SearchOption.AllDirectories))
                    {
                        string passwd = readPassFromFile(file);

                        if (!string.IsNullOrEmpty(passwd))
                        {
                            string passwd_dec = decryptPass(sid, passwd);
                            Console.WriteLine($": {file} -> {passwd_dec}");
                        }
                    }
                }
                else
                {
                    if (extra.Count() < 1)
                    {
                        ShowHelp(p);
                        exit();
                    }

                    if (!string.IsNullOrEmpty(extra[0]))
                    {
                        string passwd_dec = decryptPass(sid, extra[0]);
                        Console.WriteLine($": {extra[0]} -> {passwd_dec}");
                    }
                }
            } 
            catch (Exception ex)
            {
                Console.WriteLineStyled("Error: " + ex.Message, styleSheet);
            }

            exit();
        }

        /// <summary>
        /// Displays the header.
        /// </summary>
        static void ShowHeader()
        {
            string header = @"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@       ______                           _                               @
@       |  _  \                         | |                              @
@  __  _| | | |___  ___ _ __ _   _ _ __ | |_   It should be noted that   @
@  \ \/ / | | / _ \/ __| '__| | | | '_ \| __|  I've only tested this     @
@   >  <| |/ /  __/ (__| |  | |_| | |_) | |_   with Xshell 5 Bulid 0752  @
@  /_/\_\___/ \___|\___|_|   \__, | .__/ \__|  Xshell.exe 5.0.0028       @
@              by: synmuffin  __/ | |                                    @
@                            |___/|_|                                    @
@                                                                        @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";

            Console.WriteWithGradient(header.ToCharArray(), Color.DodgerBlue, Color.Fuchsia, 11);
            Console.WriteLine(" ");
            Console.WriteLine(" ");
        }

        /// <summary>
        /// Displays a quick help summary.
        /// </summary>
        /// <param name="p"></param>
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLineStyled("usage: xdec <-s user_sid> [-p path] [password]", styleSheet);
            Console.WriteLineStyled("decrypt a single Xshell password or every password saved in session folder.", styleSheet);
            Console.WriteLineStyled("If -p is NOT specified then xdec expects a password to be the final parameter.", styleSheet);

            Console.WriteLine(" ");
            Console.WriteLineStyled("exmaple usage (single password): ", styleSheet);
            Console.WriteLineStyled("\t xdec.exe -s S-0-0-00-1234567890-1234567890-12345678-1234 dGhpc2lzbXlhd2Vzb21ldGVzdHBhc3N3b3JkDQoNCg==", styleSheet);

            Console.WriteLine(" ");
            Console.WriteLineStyled("exmaple usage (Xshell session folder): ", styleSheet);
            Console.WriteLineStyled("\t xdec.exe -s S-0-0-00-1234567890-1234567890-12345678-1234 -p C:\\Users\\user\\Documents\\NetSarang\\Xshell\\Sessions", styleSheet);

            Console.WriteLine(" ");
            Console.WriteLineStyled("Options:", styleSheet);
            p.WriteOptionDescriptions(Console.Out);
        }

        /// <summary>
        /// Reads a password from a session file.
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        static string readPassFromFile(string file)
        {
            string fileData = File.ReadAllText(file);

            string resultString = null;
            try
            {
                resultString = Regex.Match(fileData, "Password=(.*)", RegexOptions.Multiline).Groups[1].Value;
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"ERROR: Unable to find password in session file: {file}.");
                Environment.Exit(1);
            }

            return resultString == "\r" ? null : resultString;
        }

        /// <summary>
        /// Decrypt our pass using sid.
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="pass"></param>
        /// <returns></returns>
        static string decryptPass(string sid, string pass)
        {
            /*
            string a1 = "S-1-5-21-1243134057-3636662695-74049490-1001";
            string a2 = "iwPQilZSOnw0xI6DJdCAw2p2qT3l50x8MpMTBo2tCA0qK/CcDSrbQg==";

            byte[] v1 = Convert.FromBase64String(a2);

            // compute the hash we use as a key
            // this is user SID
            // windows cmd: whoami /user
            byte[] hash = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(a1)); // this is the key

            byte[] passData = new byte[v1.Length - 0x20];
            Array.Copy(v1, 0, passData, 0, v1.Length - 0x20);

            byte[] decrypted = RC4.Decrypt(hash, passData);

            Console.WriteLine(": {0}", Encoding.ASCII.GetString(decrypted));
            */

            byte[] password = Convert.FromBase64String(pass);

            // compute the hash we use as a key
            // this is user SID
            // windows cmd: whoami /user
            byte[] key = new SHA256Managed().ComputeHash(Encoding.ASCII.GetBytes(sid)); // this is the RC4 key

            byte[] passData = new byte[password.Length - 0x20]; // padding??
            Array.Copy(password, 0, passData, 0, password.Length - 0x20);

            byte[] decrypted = RC4.Decrypt(key, passData);

            return Encoding.ASCII.GetString(decrypted);
        }

        static void exit(int ecode = 0)
        {
            Console.WriteLine(" ");
            Console.Write("press any key to continue...");
            Console.ReadKey(true);

            Environment.Exit(ecode);
        }

    }
}
