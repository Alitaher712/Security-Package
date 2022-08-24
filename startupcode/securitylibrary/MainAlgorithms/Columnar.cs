using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int n = 0;
            for (int i = 0; i < plainText.Length; i++)//Find the count of the key
            {
                if (cipherText[0] == plainText[i])
                {
                    for (int j = i + 1; j < cipherText.Length; j++)
                    {
                        if (cipherText[1] == plainText[j])
                        {
                            for (int k = j + 1; k < cipherText.Length; k++)
                            {
                                if (cipherText[2] == plainText[k])
                                {
                                    if (k - j == j - i)
                                    {
                                        n = j - i;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            int r = 0;
            for (int i = 4; i < 8; i++)
            {
                if (plainText.Length % i == 0)
                {
                    r = i;
                }
            }
            List<int> key = new List<int>(n);
            int key_siz = plainText.Length / n, itr = 0;
            if (plainText.Length % n != 0)
            {
                key_siz++;
            }
            char[,] cipher = new char[key_siz, n];
            char inc = 'x';
            for (int i = 0; i < key_siz; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    if (itr < plainText.Length)
                    {
                        cipher[i, j] = plainText[itr++];
                    }
                    else
                    {
                        cipher[i, j] = inc;
                    }
                }
            }
            for (int i = 0; i < n; i++)
            {
                int c = 0, count = 2, inre = 0;
                for (int j = 0; j < key_siz; j++)
                {

                    if ((c >= cipherText.Length || cipher[j, i] == cipherText[c]))
                    {
                        inre++;
                        if (inre == key_siz)
                        {
                            key.Add((int)Math.Ceiling(c / (float)key_siz));
                            break;
                        }
                        c++;
                    }
                    else
                    {
                        c = key_siz * (count - 1);
                        count++;
                        j = -1;
                    }
                }
            }
            return key;
        }
        public string Decrypt(string cipherText, List<int> key)
        {
            string plain = "";
            char[,] plain_mat = new char[3000, 3000];
            int rows = cipherText.Length / key.Count;
            if (cipherText.Length % key.Count != 0)
            {
                rows++;
            }
            int count = 0;
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    if (count != cipherText.Length)
                        plain_mat[j, key.IndexOf(i + 1)] = cipherText[count++];
                }
            }
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    plain += plain_mat[i, j];
                }
            }
            return plain;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string cipher = "";
            int size = plainText.Length;
            int rows = plainText.Length / key.Count;
            char[,] str1 = new char[3000, 3000];
            char[,] str2 = new char[3000, 3000];
            if (plainText.Length % key.Count != 0)
            {
                rows++;
            }
            int c = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (c != size)
                        str1[i, j] = plainText[c++];
                }
            }
            //        int[] a=new int[100];
            int x = 0;
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    str2[j, key[i] - 1] = str1[j, i];
                }
            }
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    cipher += str2[j, i];
                }

            }
            //char s = '1';
            Console.WriteLine(str2.ToString());
            Console.WriteLine(cipher);
            return cipher;
        }
    }
}