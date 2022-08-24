using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string key = "";
            char[,] arr = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    arr[i, j] = (char)(((i + j) % 26) + 97);
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (arr[plainText[i] - 97, j] == cipherText.ToLower()[i])
                    {
                        key += (char)(j + 97);
                    }
                }
            }
            int count = 1;
            int c = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (c < 5)
                {
                    for (int j = count; j < key.Length; j++)
                    {
                        if (key[i] == key[j])
                        {
                            count = j;
                            c++;
                            break;
                        }
                    }
                }
            }
            int Size = count - (c - 1);
            string Key = "";
            for (int i = 0; i < Size; i++)
            {
                Key += key[i];
            }
            return Key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            char[,] arr = new char[26, 26];
            string ke_y = "";
            string PlainText = "";
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    arr[i, j] = (char)(((i + j) % 26) + 97);
                }
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                ke_y += key[i % key.Length];
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (arr[j, ke_y[i] - 97] == cipherText.ToLower()[i])
                    {
                        PlainText += (char)(j + 97);
                    }
                }
            }
            return PlainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string ke_y = "";
            char[,] arr = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    arr[i, j] = (char)(((i + j) % 26) + 97);
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                ke_y += key[i % key.Length];
            }
            string CipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                CipherText += arr[plainText[i] - 97, ke_y[i] - 97];
            }
            return CipherText;
        }
    }
}