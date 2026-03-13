using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Linq;

namespace MifareKeyGenerator
{
    class Program
    {
        static void Main(string[] args)
        {
            int targetKeyCount = 1000;
            // Her çalışmada dosyanın üzerine yazmamak için tarihe göre isimlendiriyoruz
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string outputPath = "mifare_keys_" + timestamp + ".txt";
            
            HashSet<string> generatedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Random rnd = new Random();

            // 1. Bilinen Mifare Anahtarları
            string[] commonKeys = {
                "A0A1A2A3A4A5", "D3F7D3F7D3F7", "B0B1B2B3B4B5", "4D3A48356142",
                "1A2B3C4D5E6F", "A1B2C3D4E5F6", "4D4143415047", "5B5C5D5E5F60",
                "010203040506", "112233445566", "223344556677", "7A9E58A6DB30"
            };
            foreach (var key in commonKeys) { generatedKeys.Add(key); }

            // 2. Dinamik Tarih Patternleri (Örn: Rastgele yıllar, aylar ve günler)
            // Her çalıştığında birbirinden bağımsız tarihler üretecek
            for (int i = 0; i < 50; i++) 
            {
                int year = rnd.Next(2010, 2030);
                int month = rnd.Next(1, 13);
                int day = rnd.Next(1, 29);
                string dateKey = $"{year:D4}{month:D2}{day:D2}0000"; 
                generatedKeys.Add(dateKey.Substring(0, 12));
            }

            // 3. Farklı Tekrarlı Patternler (Rastgele oluşturulan tekrarlar)
            // Kullanıcının özellikle istediği "tekrarlı pattern" yapısı
            string hexChars = "0123456789ABCDEF";
            for (int i = 0; i < 50; i++)
            {
                // 2 karakterli tekrar (Örn: ABABABABABAB)
                string block2 = $"{hexChars[rnd.Next(16)]}{hexChars[rnd.Next(16)]}";
                generatedKeys.Add(string.Concat(Enumerable.Repeat(block2, 6)));

                // 3 karakterli tekrar (Örn: C1AC1AC1AC1A)
                string block3 = $"{hexChars[rnd.Next(16)]}{hexChars[rnd.Next(16)]}{hexChars[rnd.Next(16)]}";
                generatedKeys.Add(string.Concat(Enumerable.Repeat(block3, 4)));
                
                // 4 karakterli tekrar (Örn: F1B2F1B2F1B2)
                string block4 = $"{hexChars[rnd.Next(16)]}{hexChars[rnd.Next(16)]}{hexChars[rnd.Next(16)]}{hexChars[rnd.Next(16)]}";
                generatedKeys.Add(string.Concat(Enumerable.Repeat(block4, 3)));
            }

            // 4. Kalanları güvenli rastgele generator ile tamamla
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) {
                byte[] buffer = new byte[6]; 
                while (generatedKeys.Count < targetKeyCount) {
                    rng.GetBytes(buffer);
                    string hexKey = BitConverter.ToString(buffer).Replace("-", "").ToUpper();
                    generatedKeys.Add(hexKey);
                }
            }

            // 5. OLUŞTURULAN LİSTEYİ KARIŞTIR (SHUFFLE)
            // Böylece statik keyler ve patternler hep en başta kabak gibi sırıtmaz
            var finalKeys = generatedKeys.Take(targetKeyCount).OrderBy(x => rnd.Next()).ToList();
            File.WriteAllLines(outputPath, finalKeys);

            Console.WriteLine($"Toplam {finalKeys.Count} adet benzersiz Mifare anahtarı " + outputPath + " dosyasina yazildi.");
        }
    }
}
