using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string DesDecrypt(string cipherText, string key)
        {
            int[,] array_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] array_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] array1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] array2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] array3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] array4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] array5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] array6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] array7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] array8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] var1 = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

            int[,] var2 = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            int[,] var3 = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] var4 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string CCiipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string BbKEY = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string Lmmm = "";
            string Rmmm = "";

            int mm = 0;
            do
            {
                Lmmm = Lmmm + CCiipher[mm];
                Rmmm = Rmmm + CCiipher[mm + CCiipher.Length / 2];
                mm++;
            } while (mm < (CCiipher.Length / 2));

            //premutate key by pc-1
            string teempk = "";
            List<string> C = new List<string>();
            List<string> D = new List<string>();

            int nn = 0;
            do
            {
                int j = 0;
                while (j < 7)
                {
                    teempk = teempk + BbKEY[array_1[nn, j] - 1];
                    j++;
                }
                nn++;
            } while ((nn < 8));

            string c = teempk.Substring(0, 28);
            string d = teempk.Substring(28, 28);

            string temppp = "";

            int vv = 0;

            do
            {
                C.Add(c);
                D.Add(d);
                temppp = "";
                if (vv == 0 || vv == 1 || vv == 8 || vv == 15)
                {
                    temppp = temppp + c[0];
                    c = c.Remove(0, 1);
                    c = c + temppp;
                    temppp = "";
                    temppp = temppp + d[0];
                    d = d.Remove(0, 1);
                    d = d + temppp;
                }
                else
                {
                    temppp = temppp + c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c = c + temppp;
                    temppp = "";
                    temppp = temppp + d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d = d + temppp;
                }
                vv++;
            } while (vv <= 16);

            List<string> keys = new List<string>();
            int yy = 0;
            while (yy < D.Count)
            {
                keys.Add(C[yy] + D[yy]);
                yy++;
            }

            //k1 --> k16 by pc-2
            List<string> nkeys = new List<string>();
            int kk = 1;
            do
            {
                teempk = "";
                temppp = "";
                temppp = keys[kk];
                int i = 0;
                while (i < 8)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        teempk = teempk + temppp[array_2[i, j] - 1];
                    }
                    i++;
                }
                nkeys.Add(teempk);
                kk++;
            } while (kk < keys.Count);


            string ip = "";

            int ii = 0;
            do
            {
                int j = 0;
                while (j < 8)
                {
                    ip = ip + CCiipher[var3[ii, j] - 1];
                    j++;
                }
                ii++;
            } while (ii < 8);

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string lll = ip.Substring(0, 32);
            string rrr = ip.Substring(32, 32);

            L.Add(lll);
            R.Add(rrr);
            string x = "";
            string h = "";

            string Bt = "";
            string n = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string tt = "";
            int roww = 0;
            int column = 0;
            string ne = "";
            string pp = "";
            string lf = "";

            int iii = 0;
            while (iii < 16)
                while (iii < 16)
                {
                    L.Add(rrr);
                    n = "";
                    Bt = "";
                    lf = "";
                    pp = "";
                    sbox.Clear();
                    ne = "";
                    column = 0;
                    roww = 0;
                    tt = "";
                    for (int j = 0; j < 8; j++)
                    {
                        for (int k = 0; k < 6; k++)
                        {
                            Bt = Bt + rrr[var2[j, k] - 1];
                        }
                    }
                    int g = 0;



                    while (g < Bt.Length)
                    {
                        n = n + (nkeys[nkeys.Count - 1 - iii][g] ^ Bt[g]).ToString();
                        g++;
                    }
                    int z = 0;



                    while (z < n.Length)
                    {
                        tt = "";
                        int y = z;
                        while (y < 6 + z)
                        {
                            if (6 + z <= n.Length)
                                tt = tt + n[y];
                            y++;
                        }



                        sbox.Add(tt);
                        z = z + 6;
                    }



                    tt = "";
                    int sssbbb = 0;
                    int ss = 0;
                    while (ss < sbox.Count)
                    {
                        tt = sbox[ss];
                        x = tt[0].ToString() + tt[5];
                        h = tt[1].ToString() + tt[2] + tt[3] + tt[4];



                        roww = Convert.ToInt32(x, 2);
                        column = Convert.ToInt32(h, 2);
                        if (ss == 0)
                            sssbbb = array1[roww, column];



                        if (ss == 1)
                            sssbbb = array2[roww, column];



                        if (ss == 2)
                            sssbbb = array3[roww, column];



                        if (ss == 3)
                            sssbbb = array4[roww, column];



                        if (ss == 4)
                            sssbbb = array5[roww, column];



                        if (ss == 5)
                            sssbbb = array6[roww, column];



                        if (ss == 6)
                            sssbbb = array7[roww, column];



                        if (ss == 7)
                            sssbbb = array8[roww, column];



                        ne = ne + Convert.ToString(sssbbb, 2).PadLeft(4, '0');
                        ss++;
                    }



                    x = "";
                    h = "";
                    int kkk = 0;
                    while (kkk < 8)
                    {
                        int j = 0;
                        while (j < 4)
                        {
                            pp = pp + ne[var1[kkk, j] - 1];
                            j++;
                        }
                        kkk++;
                    }
                    int kkkk = 0;
                    do
                    {
                        lf = lf + (pp[kkkk] ^ lll[kkkk]).ToString();
                        kkkk++;
                    }
                    while (kkkk < pp.Length);



                    rrr = lf;
                    lll = L[iii + 1];
                    R.Add(rrr);
                    iii++;
                }
            string ELCC = R[16] + L[16];
            string ciphertxt = "";
            int uuu = 0;
            while (uuu < 8)
            {
                int j = 0;
                while (j < 8)
                {
                    ciphertxt = ciphertxt + ELCC[var4[uuu, j] - 1];
                    j++;
                }
                uuu++;
            }
            string ppt = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X").PadLeft(16, '0');
            return ppt;
        }

        public string DesEncrypt(string plainText, string key)
        {

            int[,] array_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] array_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] array1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] array2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] array3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] array4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] array5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] array6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] array7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] array8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] var1 = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

            int[,] var2 = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            int[,] var3 = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] var4 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string Pplain = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string BbKEY = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');



            string Lmmm = "";
            string Rmmm = "";

            int mmm = 0;
            do
            //for (int i = 0; i < Pplain.Length / 2; i++)
            {
                Lmmm = Lmmm + Pplain[mmm];
                Rmmm = Rmmm + Pplain[mmm + (Pplain.Length / 2)];
                mmm++;
            } while (mmm < Pplain.Length / 2);

            //premutate key by pc-1
            string tempkey = "";
            List<string> C = new List<string>();
            List<string> D = new List<string>();

            int o = 0;
            do
            {
                int j = 0;
                while (j < 7)
                {
                    tempkey = tempkey + BbKEY[array_1[o, j] - 1];
                    j++;
                }
                o++;
            } while (o < 8);

            //C and D
            string c = tempkey.Substring(0, 28);
            string d = tempkey.Substring(28, 28);

            string temppp = "";


            int nnn = 0;
            do
            {
                C.Add(c);
                D.Add(d);
                temppp = "";
                if (nnn == 0 || nnn == 1 || nnn == 8 || nnn == 15)
                {
                    temppp = temppp + c[0];
                    c = c.Remove(0, 1);
                    c = c + temppp;
                    temppp = "";
                    temppp = temppp + d[0];
                    d = d.Remove(0, 1);
                    d = d + temppp;
                }

                else
                {
                    temppp = temppp + c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c = c + temppp;
                    temppp = "";
                    temppp = temppp + d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d = d + temppp;
                }
                nnn++;
            } while (nnn < 17);

            List<string> keys = new List<string>();
            int zzz = 0;
            do
            {
                keys.Add(C[zzz] + D[zzz]);
                zzz++;
            } while (zzz < D.Count);

            //k1 --> k16 by pc-2
            List<string> num_of_keys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                tempkey = "";
                temppp = "";
                temppp = keys[k];

                int hh = 0;
                while (hh < 8)
                {
                    int f = 0;
                    while (f < 6)
                    {
                        tempkey = tempkey + temppp[array_2[hh, f] - 1];
                        f++;
                    }
                    hh++;
                }
                num_of_keys.Add(tempkey);
            }

            //premutation by IP for plain text
            string ipeeee = "";
            for (int i = 0; i < 8; i++)
            {
                int ttt = 0;
                while (ttt < 8)
                {
                    ipeeee = ipeeee + Pplain[var3[i, ttt] - 1];
                    ttt++;
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string lll = ipeeee.Substring(0, 32);
            string rrr = ipeeee.Substring(32, 32);

            L.Add(lll);
            R.Add(rrr);
            string x = "";
            string h = "";

            string Bt = "";
            string exorkey = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int roww = 0;
            int colmn = 0;
            string nea = "";
            string ppeee = "";
            string lf = "";

            for (int i = 0; i < 16; i++)
            {
                L.Add(rrr);
                exorkey = "";
                Bt = "";
                lf = "";
                ppeee = "";
                sbox.Clear();
                nea = "";
                colmn = 0;
                roww = 0;
                t = "";

                int w = 0;
                do
                {
                    int gg = 0;
                    while (gg < 6)
                    {
                        Bt = Bt + rrr[var2[w, gg] - 1];
                        gg++;
                    }
                    w++;
                } while (w < 8);

                int g = 0;
                while (g < Bt.Length)
                {
                    exorkey = exorkey + (num_of_keys[i][g] ^ Bt[g]).ToString();
                    g++;
                }

                for (int z = 0; z < exorkey.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exorkey.Length)
                            t = t + exorkey[y];
                    }

                    sbox.Add(t);
                }

                t = "";
                int sb = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    roww = Convert.ToInt32(x, 2);
                    colmn = Convert.ToInt32(h, 2);

                    if (s == 0)
                        sb = array1[roww, colmn];

                    if (s == 1)
                        sb = array2[roww, colmn];

                    if (s == 2)
                        sb = array3[roww, colmn];

                    if (s == 3)
                        sb = array4[roww, colmn];

                    if (s == 4)
                        sb = array5[roww, colmn];

                    if (s == 5)
                        sb = array6[roww, colmn];

                    if (s == 6)
                        sb = array7[roww, colmn];

                    if (s == 7)
                        sb = array8[roww, colmn];

                    nea = nea + Convert.ToString(sb, 2).PadLeft(4, '0');
                }

                x = "";
                h = "";

                for (int k = 0; k < 8; k++)
                {
                    int dd = 0;
                    while (dd < 4)
                    {
                        ppeee = ppeee + nea[var1[k, dd] - 1];
                        dd++;
                    }
                }

                int a = 0;
                while (a < ppeee.Length)
                {
                    lf = lf + (ppeee[a] ^ lll[a]).ToString();
                    a++;
                }

                rrr = lf;
                lll = L[i + 1];
                R.Add(rrr);
            }

            string ELCC = R[16] + L[16];
            string ciphertxt = "";

            int uuu = 0;
            while (uuu < 8)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + ELCC[var4[uuu, j] - 1];
                }
                uuu++;
            }

            string x0 = "0x";
            string ct = x0 + Convert.ToInt64(ciphertxt, 2).ToString("X");

            return ct;
        }


        public string Decrypt(string cipherText, List<string> key)
        {
            string pt = "";

            pt = DesDecrypt(cipherText, key[1]);
            pt = DesEncrypt(pt, key[0]);
            pt = DesDecrypt(pt, key[1]);

            return pt;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string ct = "";

            ct = DesEncrypt(plainText, key[0]);
            ct = DesDecrypt(ct, key[1]);
            ct = DesEncrypt(ct, key[0]);

            return ct;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}