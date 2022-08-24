using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public Dictionary<char, char> KeyDictionary(string key, string Operation)// O(1)
        {
            Dictionary<char, char> dic = new Dictionary<char, char>();
            Ceaser ceaser = new Ceaser();
            for (int i = 0; i < 26; i++)
            {
                if (Operation == "encrypt")
                    dic.Add(ceaser.alphabet[i], key[i]);
                else
                    dic.Add(key[i], ceaser.alphabet[i]);
            }
            return dic;
        }
        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            /*   SortedDictionary<char, char> KeyTable = new SortedDictionary<char, char>();
               Dictionary<char, bool> alphaList = new Dictionary<char, bool>();
               int PTLength = plainText.Length;
          //     int CTLength = cipherText.Length;
               plainText = plainText.ToLower();
               cipherText = cipherText.ToLower();
               for (int i = 0; i < PTLength; i++) // O(N)
               {
                   if (!KeyTable.ContainsKey(plainText[i])) { KeyTable.Add(plainText[i], cipherText[i]); alphaList.Add(cipherText[i], true); }
               }
               if (KeyTable.Count != 26) //O(1)
               {

                   Ceaser obj = new Ceaser();
                   string alphabet = obj.alphabet;

                   for (int i = 0; i < 26; i++)
                   {
                       if (!KeyTable.ContainsKey(alphabet[i]))
                       {
                           for (int j = 0; j < 26; j++)
                           {
                               if (!alphaList.ContainsKey(alphabet[j]))
                               {
                                   KeyTable.Add(alphabet[i], alphabet[j]);
                                   alphaList.Add(alphabet[j], true);
                                   j = 26;
                               }
                           }
                       }
                   }
               }

               string key = "";
               foreach (var item in KeyTable) // O(1)
               {
                   key += item.Value;
               }

               return key; */
            cipherText = cipherText.ToLower();
            string alpha = "abcdefghijklmnopqrstuvwxyz";

            char[] arr = new char[26];
            bool[] ar = new bool[26];
            int[] aray = new int[1000];
            if (alpha == plainText)
            {
                return cipherText.ToLower();
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                int ind = (int)plainText[i] - 97;
                arr[ind] = cipherText[i];
                ar[ind] = true;
                aray[cipherText[i]] = 1;
            }
            for (int i = 0; i < 26; i++)
            {
                if (ar[i] == false)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (aray[97 + j] != 1)
                        {
                            arr[i] = (char)(97 + j);
                            ar[i] = true;
                            aray[97 + j] = 1;
                            break;
                        }
                    }
                }
            }
            string ret = String.Join("", arr);
            //   ret = ret.ToUpper();
            Console.WriteLine(arr);
            return ret;
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            char[] chars = new char[cipherText.Length];
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (cipherText[i] == ' ')
                {
                    chars[i] = ' ';
                }
                else
                {
                    int j = key.IndexOf(cipherText[i]) + 97;
                    chars[i] = (char)j;
                }
            }
            return new string(chars);
    
}

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            char[] chars = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                {
                    chars[i] = ' ';
                }

                else
                {
                    int j = plainText[i] - 97;
                    chars[i] =char.ToLower(key[j]);
                }
            }

            return new string(chars);
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 
        
        public string AnalyseUsingCharFrequency(string cipher)
        {

            //throw new NotImplementedException();
            /*    string alphabetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
                 Dictionary<char, int> CAlphaFreq = new Dictionary<char, int>();
                 SortedDictionary<char, char> keyTable = new SortedDictionary<char, char>();
                 cipher = cipher.ToLower();
                 int CTLength = cipher.Length;
                 string key = "";
                 for (int i = 0; i < CTLength; i++)
                 {
                     if (!CAlphaFreq.ContainsKey(cipher[i]))
                     {
                         CAlphaFreq.Add(cipher[i], 0);
                     }
                     else
                     {
                         CAlphaFreq[cipher[i]]++;
                     }
                 }

                 CAlphaFreq = CAlphaFreq.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value);
                 int counter = 0;
                 foreach (var item in CAlphaFreq)
                 {
                     keyTable.Add(item.Key, alphabetFreq[counter]);
                     counter++;
                 }
                 for (int i = 0; i < CTLength; i++)
                 {
                     key += keyTable[cipher[i]];
                 }

                 return key; */

            /*
            string alphabetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            char[] arrChar = new char[26];
            bool[] arrBool = new bool[26];
            cipher = cipher.ToLower();
            int CTLength = cipher.Length;
            int cnt = 0; 
            for (int i = 0; i < CTLength; i++) {
                if (!arrChar.Contains(cipher[i])) {
                    arrChar[cnt] = cipher[i];
                    arrBool[cnt] = false;
                    cnt++; 
                }else
                {
                    arrBool[cnt] = true; 
                }
            }
            */
            string Freq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            char[] al = alpha.ToCharArray();
            // Cipher = cipher.ToLower();



            char[] arrcipher = cipher.ToLower().ToCharArray();
            int[] arr2count = new int[26];
            char[] arr3 = Freq.ToCharArray();
            char[] arrmax = new char[26];
            int y = 0;
            char[] plaintext = new char[cipher.Length];
            for (char i = 'a'; i <= 'z'; i++)
            {
                int count = 0;

                for (int j = 0; j < cipher.Length; j++)
                {
                    if (i == arrcipher[j])
                    {
                        count++;//90 --- //80
                    }
                }
                arr2count[y] = count;
                y++;
            }
            int ind;

            
            
            for (int k = 0; k < arr2count.Length; k++)
            {
                int kk = arr2count.Max();
                ind = arr2count.ToList().IndexOf(kk);
                arrmax[k] = al[ind];
                arr2count.SetValue(-1, ind);
            }
            for (int j = 0; j < cipher.Length; j++)
            {
                if (arrcipher[j] == arrmax[0])
                {
                    plaintext[j] += 'e';
                }
                if (arrcipher[j] == arrmax[1])
                {
                    plaintext[j] += 't';
                }
                if (arrcipher[j] == arrmax[2])
                {
                    plaintext[j] += 'a';
                }
                if (arrcipher[j] == arrmax[3])
                {
                    plaintext[j] += 'o';
                }
                if (arrcipher[j] == arrmax[4])
                {
                    plaintext[j] += 'i';
                }
                if (arrcipher[j] == arrmax[5])
                {
                    plaintext[j] += 'n';
                }
                if (arrcipher[j] == arrmax[6])
                {
                    plaintext[j] += 's';
                }
                if (arrcipher[j] == arrmax[7])
                {
                    plaintext[j] += 'r';
                }
                if (arrcipher[j] == arrmax[8])
                {
                    plaintext[j] += 'h';
                }
                if (arrcipher[j] == arrmax[9])
                {
                    plaintext[j] += 'l';
                }
                if (arrcipher[j] == arrmax[10])
                {
                    plaintext[j] += 'd';
                }
                if (arrcipher[j] == arrmax[11])
                {
                    plaintext[j] += 'c';
                }
                if (arrcipher[j] == arrmax[12])
                {
                    plaintext[j] += 'u';
                }
                if (arrcipher[j] == arrmax[13])
                {
                    plaintext[j] += 'm';
                }
                if (arrcipher[j] == arrmax[14])
                {
                    plaintext[j] += 'f';
                }
                if (arrcipher[j] == arrmax[15])
                {
                    plaintext[j] += 'p';
                }
                if (arrcipher[j] == arrmax[16])
                {
                    plaintext[j] += 'g';
                }
                if (arrcipher[j] == arrmax[17])
                {
                    plaintext[j] += 'w';
                }
                if (arrcipher[j] == arrmax[18])
                {
                    plaintext[j] += 'y';
                }
                if (arrcipher[j] == arrmax[19])
                {
                    plaintext[j] += 'b';
                }
                if (arrcipher[j] == arrmax[20])
                {
                    plaintext[j] += 'v';
                }
                if (arrcipher[j] == arrmax[21])
                {
                    plaintext[j] += 'k';
                }
                if (arrcipher[j] == arrmax[22])
                {
                    plaintext[j] += 'x';
                }
                if (arrcipher[j] == arrmax[23])
                {
                    plaintext[j] += 'j';
                }
                if (arrcipher[j] == arrmax[24])
                {
                    plaintext[j] += 'q';
                }
                if (arrcipher[j] == arrmax[25])
                {
                    plaintext[j] += 'z';
                }
            }
            Console.WriteLine(plaintext);
            return new string(plaintext);

        }
    }
}
