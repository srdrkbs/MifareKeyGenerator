using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace MifareKeyGenerator
{
    class Program
    {
        static void Main(string[] args)
        {
            int targetKeyCount = 1000;
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string outputPath = "mifare_keys_" + timestamp + ".txt";
            
            HashSet<string> generatedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Random rnd = new Random();

            // 1. İnsan (IT/Geliştirici) Psikolojisi ile Kurallar Seti
            var humanGenKeys = GenerateHumanPsychologyKeys();
            foreach (var key in humanGenKeys) { generatedKeys.Add(key); }

            // 2. Kalanları güvenli rastgele generator ile tamamla
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) {
                byte[] buffer = new byte[6]; 
                while (generatedKeys.Count < targetKeyCount) {
                    rng.GetBytes(buffer);
                    string hexKey = BitConverter.ToString(buffer).Replace("-", "").ToUpper();
                    generatedKeys.Add(hexKey);
                }
            }

            // Oluşturulan listeyi karıştır
            var finalKeys = generatedKeys.Take(targetKeyCount).OrderBy(x => rnd.Next()).ToList();
            File.WriteAllLines(outputPath, finalKeys);

            Console.WriteLine($"Toplam {finalKeys.Count} adet benzersiz Mifare anahtarı " + outputPath + " dosyasina yazildi.");
            Console.WriteLine("İnsan psikolojisi ile üretilen örnek anahtarlar:");
            foreach(var k in humanGenKeys.Take(10)) Console.WriteLine(k);
        }

        static List<string> GenerateHumanPsychologyKeys() 
        {
            var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            // Eğer string baştan sonra sadece (0-9, A-F, a-f) den oluşuyorsa direkt pad yap. 
            // Hex formatında DEĞİLSE arka planda UTF-8 byte dizisine çevir (böylece tüm I, Ş, Ğ vb. karakterler hex byte dizilerine döner)
            string EncodeToMifareHex(string input) {
                string resultHex = "";
                
                // Normal hex mi diye bakıyoruz 
                bool isAlreadyHex = Regex.IsMatch(input, @"\A\b[0-9a-fA-F]+\b\Z");

                if (isAlreadyHex) {
                    resultHex = input;
                } else {
                    // Cümleyi tamamen byte'a dök (Örn: "ŞİFRE" -> c59e c4b0 4652 45)
                    var bytes = Encoding.UTF8.GetBytes(input);
                    resultHex = BitConverter.ToString(bytes).Replace("-", "");
                }

                // Mifare için net 12 Karakter sınırını koruyoruz 
                if (resultHex.Length > 12) {
                    resultHex = resultHex.Substring(0, 12);
                } else if (resultHex.Length < 12) {
                    resultHex = resultHex.PadRight(12, '0');
                }

                return resultHex.ToUpper();
            }

            // A) TÜRK IT/YAZILIMCI PSİKOLOJİSİ
            string[] trKeywords = { "1453", "1905", "1907", "1923", "06", "34", "35", "1903" };
            // Türkçe harf içeren ("şifre1", "türk12" vb.) şifreler, Hex karşılıklarına başarıyla UTF-8 byte array ile dönüşecek
            string[] trWords = { "qweasd", "asdzxc", "admin1", "şifre1", "türk12", "123456", "112233", "654321", "197020" };

            foreach (var kw in trKeywords) keys.Add(EncodeToMifareHex(kw));
            foreach (var w in trWords) keys.Add(EncodeToMifareHex(w));

            // B) GLOBAL/YABANCI IT/YAZILIMCI PSİKOLOJİSİ
            // Zaten saf HEX yazımları
            string[] globalKwHex = { 
                "C0FFEE", "BADC0DE", "DEADBEEF", "DEADC0DE", "FEEDFACE", 
                "8BADF00D", "CAFEBABE", "BAADF00D", "DEFEC8ED"
            };
            
            // Byte'a dönüştürülecek düz metin global şifreler
            string[] globalWords = { "qwerty", "admin", "password", "root12", "123qwe", "!@#$%" };

            foreach (var kw in globalKwHex) keys.Add(EncodeToMifareHex(kw));
            foreach (var w in globalWords) keys.Add(EncodeToMifareHex(w));

            // C) ORTAK DAVRANIŞSAL KALIPLAR
            keys.Add("314159265358"); 
            keys.Add("271828182845"); 
            keys.Add("202603130000"); 
            keys.Add("000020260313");

            return keys.ToList();
        }
    }
}
