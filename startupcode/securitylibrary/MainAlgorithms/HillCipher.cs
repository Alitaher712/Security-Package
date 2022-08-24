using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> mayBeKey = new List<int>();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            mayBeKey = new List<int>(new[] { i, j, k, l });
                            List<int> aa = Encrypt(plainText, mayBeKey);
                            if (aa.SequenceEqual(cipherText))
                            {
                                return mayBeKey;
                            }

                        }
                    }
                }
            }

            throw new InvalidAnlysisException();
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainText = new List<int>();
            if (key.Count == 4)
            {
                int det = ((((key[0] * key[3] - key[1] * key[2]) % 26) + 26) % 26);
                if (det == 1)
                {
                    det = 1;
                }
                else if (det == 3)
                {
                    det = 9;
                }
                else if (det == 5)
                {
                    det = 21;
                }
                else if (det == 7)
                {
                    det = 15;
                }
                else if (det == 9)
                {
                    det = 3;
                }
                else if (det == 11)
                {
                    det = 19;
                }
                else if (det == 15)
                {
                    det = 7;
                }
                else if (det == 17)
                {
                    det = 23;
                }
                else if (det == 19)
                {
                    det = 11;
                }
                else if (det == 21)
                {
                    det = 5;
                }
                else if (det == 23)
                {
                    det = 17;
                }
                else if (det == 25)
                {
                    det = 25;
                }
                else throw new Exception();
                Console.WriteLine(det);
                int d1 = ((((key[0] * det) % 26) + 26) % 26);
                int d2 = ((((-1 * key[1] * det) % 26) + 26) % 26);
                int d3 = ((((-1 * key[2] * det) % 26) + 26) % 26);
                int d4 = ((((key[3] * det) % 26) + 26) % 26);
                List<int> plain = new List<int>() { d4, d2, d3, d1 };
                for (int i = 0; i < 4; i++)
                {
                    Console.WriteLine(plain[i]);
                }
                int a1, a2 = 0;
                for (int i = 0; i < cipherText.Count; i += 2)
                {
                    a1 = 0; a2 = 0;
                    a1 = (cipherText[i + 1] * plain[1] + plain[0] * cipherText[i]) % 26;
                    a2 = (cipherText[i + 1] * plain[3] + plain[2] * cipherText[i]) % 26;
                    plainText.Add(a1);
                    plainText.Add(a2);
                }

            }

            else if (key.Count == 9)
            {
                int k0, k1, k2 = 0;
                k0 = key[0] * (key[4] * key[8] - key[5] * key[7]);
                k1 = key[1] * (key[3] * key[8] - key[5] * key[6]);
                k2 = key[2] * (key[3] * key[7] - key[4] * key[6]);
                int d = (((k0 - k1 + k2) % 26) + 26) % 26;
                if (d == 1) d = 1;
                else if (d == 3) d = 9;
                else if (d == 5) d = 21;
                else if (d == 7) d = 15;
                else if (d == 9) d = 3;
                else if (d == 11) d = 19;
                else if (d == 15) d = 7;
                else if (d == 17) d = 23;
                else if (d == 19) d = 11;
                else if (d == 21) d = 5;
                else if (d == 23) d = 17;
                else if (d == 25) d = 25;
                else throw new Exception();
                int[] adjecent = new int[9];
                List<int> inverse_mat = new List<int>();
                adjecent[0] = (((key[4] * key[8] - key[5] * key[7]) * d) % 26);
                adjecent[1] = ((((key[3] * key[8] - key[5] * key[6]) * -1) * d) % 26);
                adjecent[2] = (((key[3] * key[7] - key[4] * key[6]) * d) % 26);
                adjecent[3] = ((((key[1] * key[8] - key[7] * key[2]) * -1) * d) % 26);
                adjecent[4] = (((key[0] * key[8] - key[2] * key[6]) * d) % 26);
                adjecent[5] = ((((key[0] * key[7] - key[6] * key[1]) * -1) * d) % 26);
                adjecent[6] = (((key[1] * key[5] - key[2] * key[4]) * d) % 26);
                adjecent[7] = ((((key[0] * key[5] - key[2] * key[3]) * -1) * d) % 26);
                adjecent[8] = (((key[0] * key[4] - key[1] * key[3]) * d) % 26);
                inverse_mat.Add(adjecent[0]);
                inverse_mat.Add(adjecent[3]);
                inverse_mat.Add(adjecent[6]);
                inverse_mat.Add(adjecent[1]);
                inverse_mat.Add(adjecent[4]);
                inverse_mat.Add(adjecent[7]);
                inverse_mat.Add(adjecent[2]);
                inverse_mat.Add(adjecent[5]);
                inverse_mat.Add(adjecent[8]);

                for (int i = 0; i < inverse_mat.Count; i++)
                {
                    if (inverse_mat[i] < 0) inverse_mat[i] += 26;
                }
                for (int i = 0; i < cipherText.Count; i++)
                {
                    Console.WriteLine(cipherText[i]);
                }

                for (int i = 0; i < cipherText.Count; i += 3)
                {
                    int p1, p2, p3 = 0;
                    p1 = inverse_mat[0] * cipherText[i] + inverse_mat[1] * cipherText[i + 1] + inverse_mat[2] * cipherText[i + 2];
                    p2 = inverse_mat[3] * cipherText[i] + inverse_mat[4] * cipherText[i + 1] + inverse_mat[5] * cipherText[i + 2];
                    p3 = inverse_mat[6] * cipherText[i] + inverse_mat[7] * cipherText[i + 1] + inverse_mat[8] * cipherText[i + 2];
                    plainText.Add(p1 % 26);
                    plainText.Add(p2 % 26);
                    plainText.Add(p3 % 26);
                }

            }

            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherText = new List<int>();
            int sz = (int)Math.Sqrt(key.Count);
            if (sz * sz != key.Count)
            {
                sz++;
            }
            List<List<int>> mat1 = new List<List<int>>();
            int k = 0;
            for (int i = 0; i < key.Count / sz; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < sz; j++)
                {
                    tmp.Add(key[k]);
                    k++;
                }
                mat1.Add(tmp);
            }
            List<List<int>> mat2 = new List<List<int>>();
            k = 0;
            for (int i = 0; i < plainText.Count / sz; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < sz; j++)
                {
                    tmp.Add(plainText[k]);
                    k++;
                }
                mat2.Add(tmp);
            }
            for (int i = 0; i < plainText.Count / sz; i++)
            {
                List<int> mal = new List<int>();
                for (int r = 0; r < sz; r++)
                {
                    int tmp = 0;
                    for (int c = 0; c < sz; c++)
                    {
                        tmp += (mat1[r][c] * mat2[i][c]);
                    }
                    tmp %= 26;
                    if (tmp < 0)
                    {
                        tmp += 26;
                    }
                    mal.Add(tmp);
                }
                for (int j = 0; j < sz; j++)
                {
                    cipherText.Add(mal[j]);
                }
            }
            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();
            List<int> plain = new List<int>();
            List<int> ciph = new List<int>();
            bool flag = false;
            int x = 0, y = 0, z = 0, d = 0;
            for (x = 0; x < 3; x++)
            {
                for (y = 0; y < 3; y++)
                {
                    for (z = 0; z < 3; z++)
                    {
                        if (x != y && x != z && y != z)
                        {
                            plain.Add(plainText[x]);
                            plain.Add(plainText[x + 3]);
                            plain.Add(plainText[x + 6]);
                            plain.Add(plainText[y]);
                            plain.Add(plainText[y + 3]);
                            plain.Add(plainText[y + 6]);
                            plain.Add(plainText[z]);
                            plain.Add(plainText[z + 3]);
                            plain.Add(plainText[z + 6]);

                            int p0, p1, p2 = 0;

                            p0 = plain[0] * (plain[4] * plain[8] - plain[5] * plain[7]);
                            p1 = plain[1] * (plain[3] * plain[8] - plain[5] * plain[6]);
                            p2 = plain[2] * (plain[3] * plain[7] - plain[4] * plain[6]);

                            d = p0 - p1 + p2;
                            d %= 26;

                            if (d < 0) d += 26;

                            if (d == 1)
                            {
                                d = 1;
                                flag = true;
                            }
                            else if (d == 3)
                            {
                                d = 9;
                                flag = true;
                            }
                            else if (d == 5)
                            {
                                d = 21;
                                flag = true;
                            }
                            else if (d == 7)
                            {
                                d = 15;
                                flag = true;
                            }
                            else if (d == 9)
                            {
                                d = 3;
                                flag = true;
                            }
                            else if (d == 11)
                            {
                                d = 19;
                                flag = true;
                            }
                            else if (d == 15)
                            {
                                d = 7;
                                flag = true;
                            }
                            else if (d == 17)
                            {
                                d = 23;
                                flag = true;
                            }
                            else if (d == 19)
                            {
                                d = 11;
                                flag = true;
                            }
                            else if (d == 21)
                            {
                                d = 5;
                                flag = true;
                            }
                            else if (d == 23)
                            {
                                d = 17;
                                flag = true;
                            }
                            else if (d == 25)
                            {
                                d = 25;
                                flag = true;
                            }

                        }
                        if (flag) break;
                    }
                    if (flag) break;
                }
                if (flag) break;
            }
            Console.WriteLine(d);
            if (!flag) throw new InvalidAnlysisException();
            ciph.Add(cipherText[0]);
            ciph.Add(cipherText[3]);
            ciph.Add(cipherText[6]);
            ciph.Add(cipherText[1]);
            ciph.Add(cipherText[4]);
            ciph.Add(cipherText[7]);
            ciph.Add(cipherText[2]);
            ciph.Add(cipherText[5]);
            ciph.Add(cipherText[8]);
            int[] adjecent = new int[9];
            List<int> inverse_mat = new List<int>();
            //for (int i = 0; i < 9; i++)
            //{
            //    Console.WriteLine(adjecent[i]);
            //}
            //for (int i = 0; i < 9; i++)
            //{
            //    Console.WriteLine(cipherText[i]);
            //}
            adjecent[0] = (((plain[4] * plain[8] - plain[5] * plain[7]) * d) % 26);
            adjecent[1] = ((((plain[3] * plain[8] - plain[5] * plain[6]) * -1) * d) % 26);
            adjecent[2] = (((plain[3] * plain[7] - plain[4] * plain[6]) * d) % 26);
            adjecent[3] = ((((plain[1] * plain[8] - plain[7] * plain[2]) * -1) * d) % 26);
            adjecent[4] = (((plain[0] * plain[8] - plain[2] * plain[6]) * d) % 26);
            adjecent[5] = ((((plain[0] * plain[7] - plain[6] * plain[1]) * -1) * d) % 26);
            adjecent[6] = (((plain[1] * plain[5] - plain[2] * plain[4]) * d) % 26);
            adjecent[7] = ((((plain[0] * plain[5] - plain[2] * plain[3]) * -1) * d) % 26);
            adjecent[8] = (((plain[0] * plain[4] - plain[1] * plain[3]) * d) % 26);

            inverse_mat.Add(adjecent[0]);
            inverse_mat.Add(adjecent[3]);
            inverse_mat.Add(adjecent[6]);
            inverse_mat.Add(adjecent[1]);
            inverse_mat.Add(adjecent[4]);
            inverse_mat.Add(adjecent[7]);
            inverse_mat.Add(adjecent[2]);
            inverse_mat.Add(adjecent[5]);
            inverse_mat.Add(adjecent[8]);
            for (int i = 0; i < inverse_mat.Count; i++)
            {
                if (inverse_mat[i] < 0) inverse_mat[i] += 26;
            }
            for (int i = 0; i < 9; i++)
            {
                Console.WriteLine(adjecent[i]);
            }
            for (int i = 0; i < inverse_mat.Count; i += 3)
            {
                int k1, k2, k3 = 0;
                k1 = ciph[i] * inverse_mat[0] + ciph[i + 1] * inverse_mat[3] + ciph[i + 2] * inverse_mat[6];
                k2 = ciph[i] * inverse_mat[1] + ciph[i + 1] * inverse_mat[4] + ciph[i + 2] * inverse_mat[7];
                k3 = ciph[i] * inverse_mat[2] + ciph[i + 1] * inverse_mat[5] + ciph[i + 2] * inverse_mat[8];
                key.Add(k1 % 26);
                key.Add(k2 % 26);
                key.Add(k3 % 26);
            }
            return key;
        }

    }
}
