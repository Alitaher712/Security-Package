using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
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
            int count = 0;
            int c = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = count; j < key.Length; j++)
                {
                    if (plainText[i] == key[j])
                    {
                        count = j;
                        c++;
                        break;
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
            string PlaintText = "";
            char[,] arr = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    arr[i, j] = (char)(((i + j) % 26) + 97);
                }
            }
            for (int i = 0; key.Length < cipherText.Length; i++)
            {
                for (int c = 0; c < 26; c++)
                {
                    if (arr[c, key[i] - 97] == cipherText.ToLower()[i])
                    {
                        key += (char)(c + 97);
                    }
                }
            }
            for (int k = 0; k < cipherText.Length; k++)
            {
                for (int c = 0; c < 26; c++)
                {
                    if (arr[c, key[k] - 97] == cipherText.ToLower()[k])
                    {
                        PlaintText += (char)(c + 97);
                    }
                }
            }
            return PlaintText;
        }

        public string Encrypt(string plainText, string key)
        {
            string CipherText = "";
            char[,] arr = new char[26, 26];
            int e = plainText.Length - key.Length;
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    arr[i, j] = (char)(((i + j) % 26) + 97);
                }
            }
            for (int i = 0; i < e; i++)
            {
                key += plainText[i];
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                CipherText += arr[plainText[i] - 97, key[i] - 97];
            }
            return CipherText;
        }
    }
}