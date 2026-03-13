using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Linq;
using System.Text;

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
            // Hex string'e çevirmek için yardımcı fonksiyon (Mifare 6 byte = 12 hex karakter)
            string ToHexPadded(string input) {
                var bytes = Encoding.UTF8.GetBytes(input);
                var hex = BitConverter.ToString(bytes).Replace("-", "");
                if (hex.Length > 12) hex = hex.Substring(0, 12);
                else if (hex.Length < 12) hex = hex.PadRight(12, '0');
                return hex.ToUpper();
            }

            // A) TÜRK IT/YAZILIMCI PSİKOLOJİSİ
            // 1. Plakalar, tutulan takımlar, kuruluş tarihleri
            string[] trKeywords = { "1453", "1905", "1907", "1923", "06", "34", "35", "1903" };
            // 2. Türkçe klavye klasik el alışkanlıkları ve basit kelimeler (Hex formatına döküldüğünde)
            string[] trWords = { "qweasd", "asdzxc", "admin1", "sifre1", "123456", "112233", "654321", "197020", "turk12" };

            foreach (var kw in trKeywords) keys.Add(ToHexPadded(kw));
            foreach (var w in trWords) keys.Add(ToHexPadded(w));

            // B) GLOBAL/YABANCI IT/YAZILIMCI PSİKOLOJİSİ
            // 1. Leet Speak (1337) ve popüler geek kültürleri
            string[] globalKw = { 
                "C0FFEE", "BADC0DE", "DEADBEEF", "DEADC0DE", "FEEDFACE", 
                "8BADF00D", "CAFEBABE", "BAADF00D", "DEFEC8ED"
            };
            // 2. Global klavye patenleri ve popüler zafiyet şifreleri
            string[] globalWords = { "qwerty", "admin", "password", "root12", "123qwe", "!@#$%" };

            foreach (var kw in globalKw) {
                // Eğer zaten hex formatına uygunsa (uzunluğu 6-12 arası) direkt al, sonunu 0 ile doldur
                if(System.Text.RegularExpressions.Regex.IsMatch(kw, @"\A\b[0-9a-fA-F]+\b\Z")) {
                    keys.Add(kw.PadRight(12, '0'));
                } else {
                    keys.Add(ToHexPadded(kw));
                }
            }
            foreach (var w in globalWords) keys.Add(ToHexPadded(w));

            // C) ORTAK DAVRANIŞSAL KALIPLAR
            // 1. Asal sayılar ve matematiksel sabitler (Pi, e vb)
            keys.Add("314159265358"); // Pi'nin ilk basamakları
            keys.Add("271828182845"); // e sayısının ilk basamakları
            // 2. Sistemin kurulduğu yıl/ay (Örn: 2026 yılı için default bir yapı)
            keys.Add("202603130000"); 
            keys.Add("000020260313");

            return keys.ToList();
        }
    }
}
