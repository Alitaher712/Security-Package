using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int x = 0;
            int k = 0;
            for (int i = 1; i < plainText.Length; i++)
            {
                string ciph = Encrypt(plainText, i);
                if (ciph.ToLower() == cipherText.ToLower())
                {
                    x = i;
                    break;
                }
            }

            return x;
        }

        void set(ref string pl, int x)
        {
            while (x > 0)
            {
                pl += " ";
                x--;
            }
        }
        public string Decrypt(string cipherText, int key)
        {
            int n = (int)Math.Ceiling((cipherText.Length / (double)key));
            string[,] mat = new string[key, n];
            int c = 0;
            int lett = (n * key) - cipherText.Length;
            set(ref cipherText, lett);
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    mat[i, j] = cipherText.ToLower()[c].ToString();
                    c++;
                }
            }
            string PlaintText = "";
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (mat[j, i] != " ")
                        PlaintText += mat[j, i];
                }
            }
            return PlaintText;
        }

        public string Encrypt(string plainText, int key)
        {
            int n = (int)Math.Ceiling((plainText.Length / (double)key));
            string[,] mat = new string[n, key];
            string CipherText = "";
            int c = 0;
            int lett = (n * key) - plainText.Length;
            string temp = plainText;
            for (int i = plainText.Length; i <= (n * key); i++)
            {
                temp += " ";
            }
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    mat[i, j] = temp[c++].ToString();
                }
            }
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    if (mat[j, i] != " ")
                    {
                        CipherText += mat[j, i];
                    }
                }
            }
            return CipherText.ToUpper();
        }
    }
}