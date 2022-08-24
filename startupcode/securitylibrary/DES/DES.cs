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
    /// 


    public class DES : CryptographicTechnique
    {
        int[,] Array_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };
        int[,] Array_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };
        string String_1 = "";
        string String_2 = "";

        List<string> The_List_1 = new List<string>();
        string The_Temp = "";
        List<string> The_List_2 = new List<string>();

        int[,] var_1 = new int[4, 16]
          { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
            { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
            { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
            { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        int[,] var_2 = new int[4, 16]
          { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
            { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
            { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
            { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        int[,] var_3 = new int[4, 16]
            { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
            { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
            { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
            { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        int[,] var_4 = new int[4, 16]
           { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
            { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
            { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
            { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        int[,] var_5 = new int[4, 16]
            { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
            { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
            { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
            { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        int[,] var_6 = new int[4, 16]
            { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
            { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
            { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
            { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        int[,] var_7 = new int[4, 16]
            { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
            { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
            { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
            { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        int[,] var_8 = new int[4, 16]
            { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
            { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
            { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
            { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

        int[,] Array_3 = new int[8, 4]
            { { 16, 7, 20, 21 }, { 29, 12, 28, 17 },
            { 1, 15, 23, 26 }, { 5, 18, 31, 10 },
            { 2, 8, 24, 14 }, { 32, 27, 3, 9 },
            { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
        int[,] array_4 = new int[8, 6]
            { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 },
            { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 },
            { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 },
            { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };
        int[,] array_5 = new int[8, 8]
        { { 58, 50, 42, 34, 26, 18, 10, 2 },{ 60, 52, 44, 36, 28, 20, 12, 4 },
            { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 },
            { 57, 49, 41, 33, 25, 17, 9, 1 },{ 59, 51, 43, 35, 27, 19, 11, 3 },
            { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };
        int[,] array_6 = new int[8, 8]
        { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 },
            { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 },
            { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


        public override string Decrypt(string cipherText, string key)
        {
            string the_cipheeer;
            the_cipheeer = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string The_keeeeey;
            The_keeeeey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            int sub;
            int var_9 = 0;
            int lenght_divides_two;
            lenght_divides_two = the_cipheeer.Length / 2;

            do

            {

                sub = 1;

                bool falg;
                if (sub == 1)
                {
                    falg = true;
                }
                else
                {
                    falg = false;
                }
                switch (falg)
                {
                    case true:
                        {
                            int lenght;
                            lenght = the_cipheeer.Length;

                            String comaprision;
                            comaprision = (the_cipheeer[var_9]).ToString();
                            String_1 += comaprision;
                            String_2 += the_cipheeer[var_9 + lenght_divides_two];
                            var_9++;
                            break;
                        }
                    case false:
                        {
                            int lenght;
                            lenght = the_cipheeer.Length;
                            String comaprision;
                            break;
                        }
                    default:
                        {
                            break;
                        }


                }

            } while (var_9 < lenght_divides_two);



            int var_10 = 0;
            int seven = 7;
            int eight = 8;
            int one = 1;
            do

            {
                bool flag = true;
                if (flag == false)
                {
                    break;
                }
                else
                {
                    int nn = 0;
                    while (nn < seven)

                    {

                        The_Temp += The_keeeeey[Array_1[var_10, nn] - one];
                        nn++;

                    }
                    var_10++;
                }

            } while (var_10 < eight);





            //C and D
            string The_list_1_substring;
            The_list_1_substring = The_Temp.Substring(0, 28);
            string The_list_2_substring;
            The_list_2_substring = The_Temp.Substring(28, 28);

            string stringggg_5 = "";
            for (int i = 0; i <= 16; i++)
            {
                The_List_1.Add(The_list_1_substring);
                The_List_2.Add(The_list_2_substring);
                stringggg_5 = "";
                if (i == 0)
                {
                    stringggg_5 += The_list_1_substring[0];
                    The_list_1_substring = The_list_1_substring.Remove(0, 1);
                    The_list_1_substring += stringggg_5;
                    stringggg_5 = "";
                    stringggg_5 += The_list_2_substring[0];
                    The_list_2_substring = The_list_2_substring.Remove(0, 1);
                    The_list_2_substring += stringggg_5;
                }
                else if (i == 8)
                {
                    stringggg_5 += The_list_1_substring[0];
                    The_list_1_substring = The_list_1_substring.Remove(0, 1);
                    The_list_1_substring += stringggg_5;
                    stringggg_5 = "";
                    stringggg_5 += The_list_2_substring[0];
                    The_list_2_substring = The_list_2_substring.Remove(0, 1);
                    The_list_2_substring += stringggg_5;
                }
                else if (i == 1)
                {
                    stringggg_5 += The_list_1_substring[0];
                    The_list_1_substring = The_list_1_substring.Remove(0, 1);
                    The_list_1_substring += stringggg_5;
                    stringggg_5 = "";
                    stringggg_5 += The_list_2_substring[0];
                    The_list_2_substring = The_list_2_substring.Remove(0, 1);
                    The_list_2_substring += stringggg_5;
                }
                else if (i == 15)
                {
                    stringggg_5 += The_list_1_substring[0];
                    The_list_1_substring = The_list_1_substring.Remove(0, 1);
                    The_list_1_substring += stringggg_5;
                    stringggg_5 = "";
                    stringggg_5 += The_list_2_substring[0];
                    The_list_2_substring = The_list_2_substring.Remove(0, 1);
                    The_list_2_substring += stringggg_5;
                }
                else
                {
                    stringggg_5 += The_list_1_substring.Substring(0, 2);
                    The_list_1_substring = The_list_1_substring.Remove(0, 2);
                    The_list_1_substring += stringggg_5;
                    stringggg_5 = "";
                    stringggg_5 += The_list_2_substring.Substring(0, 2);
                    The_list_2_substring = The_list_2_substring.Remove(0, 2);
                    The_list_2_substring += stringggg_5;
                }
            }


            List<string> keys = new List<string>();
            for (int i = 0; i < The_List_2.Count; i++)
            {
                string s = The_List_1[i] + The_List_2[i]; 
                keys.Add(s);
            }

           
            List<string> nkeys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                The_Temp = "";
               
                stringggg_5 = keys[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                        The_Temp = The_Temp + stringggg_5[Array_2[i, j] - 1];
                    
                }

                nkeys.Add(The_Temp);
            }

           
            string ip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                    ip += the_cipheeer[array_5[i, j] - 1];
                
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = ip.Substring(0, 32);
            string r = ip.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebit = "";
            string exork = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";

            for (int i = 0; i < 16; i++)
            {
                L.Add(r);
                exork = "";
                ebit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        ebit = ebit + r[array_4[j, k] - 1];
                    }
                }

                for (int g = 0; g < ebit.Length; g++)
                {
                    exork = exork + (nkeys[nkeys.Count - 1 - i][g] ^ ebit[g]).ToString();
                }

                for (int z = 0; z < exork.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exork.Length)
                            t = t + exork[y];
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

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);

                    switch (s)
                    {
                        case 0:
                            sb = var_1[row, col];
                            break;
                        case 1:
                            sb = var_2[row, col];
                            break;
                        case 2:
                            sb = var_3[row, col];
                            break;
                        case 3:
                            sb = var_4[row, col];
                            break;
                        case 4:
                            sb = var_5[row, col];
                            break;
                        case 5:
                            sb = var_6[row, col];
                            break;
                        case 6:
                            sb = var_7[row, col];
                            break;
                        case 7:
                            sb = var_8[row, col];
                            break;
                        default:
                            sb = sb;
                            break;
                    }


                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                }

                x = "";
                h = "";

                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp = pp + tsb[Array_3[k, j] - 1];
                    }
                }

                for (int k = 0; k < pp.Length; k++)
                {
                    lf = lf + (pp[k] ^ l[k]).ToString();
                }

                r = lf;
                l = L[i + 1];
                R.Add(r);
            }

            string r16l16 = R[16] + L[16];
            string ciphertxt = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + r16l16[array_6[i, j] - 1];
                }
            }
            string pt = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X").PadLeft(16, '0');
            return pt;
        }

        public override string Encrypt(string plainText, string key)
        {

            string The_plain_text;
            string The_plaaain;
            The_plaaain = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string The_keeeeey;
            The_keeeeey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            int sub;
            int var_9 = 0;
            int lenght_divides_two;
            lenght_divides_two = The_plaaain.Length / 2;

            do

            {

                sub = 1;

                bool falg;
                if (sub == 1)
                {
                    falg = true;
                }
                else
                {
                    falg = false;
                }
                switch (falg)
                {
                    case true:
                        {
                            int lenght;
                            lenght = The_plaaain.Length;

                            String comaprision;
                            comaprision = (The_plaaain[var_9]).ToString();
                            String_1 = String_1 + comaprision;
                            String_2 = String_2 + The_plaaain[var_9 + lenght_divides_two];
                            var_9++;
                            break;
                        }
                    case false:
                        {
                            int lenght;
                            lenght = The_plaaain.Length;
                            String comaprision;
                            break;
                        }
                    default:
                        {
                            break;
                        }


                }

            } while (var_9 < lenght_divides_two);


            //premutate key by pc-1

            int var_10;
            var_10 = 0;
            int seven = 7;
            int eight = 8;
            int one = 1;
            do

            {
                bool flag = true;
                if (flag == false)
                {
                    break;
                }
                else
                {
                    int nn = 0;
                    while (nn < seven)

                    {

                        The_Temp += The_keeeeey[Array_1[var_10, nn] - one];
                        nn++;

                    }
                    var_10++;
                }

            } while (var_10 < eight);


            //C and D
            string The_list_1_substring;
            The_list_1_substring = The_Temp.Substring(0, 28);
            string The_list_2_substring;
            The_list_2_substring = The_Temp.Substring(28, 28);

            string stringggg_5 = "";
            for (int i = 0; i <= 16; i++)
            {
                The_List_1.Add(The_list_1_substring);
                The_List_2.Add(The_list_2_substring);
                stringggg_5 = "";
                if (i == 0)
                {
                    stringggg_5 += The_list_1_substring[0];
                    The_list_1_substring = The_list_1_substring.Remove(0, 1);
                    The_list_1_substring += stringggg_5;
                    stringggg_5 = "";
                    stringggg_5 += The_list_2_substring[0];
                    The_list_2_substring = The_list_2_substring.Remove(0, 1);
                    The_list_2_substring += stringggg_5;
                }
                else if (i == 8)
                {
                    stringggg_5 += The_list_1_substring[0];
                    The_list_1_substring = The_list_1_substring.Remove(0, 1);
                    The_list_1_substring += stringggg_5;
                    stringggg_5 = "";
                    stringggg_5 += The_list_2_substring[0];
                    The_list_2_substring = The_list_2_substring.Remove(0, 1);
                    The_list_2_substring += stringggg_5;
                }
                else if (i == 1)
                {
                    stringggg_5 += The_list_1_substring[0];
                    The_list_1_substring = The_list_1_substring.Remove(0, 1);
                    The_list_1_substring += stringggg_5;
                    stringggg_5 = "";
                    stringggg_5 += The_list_2_substring[0];
                    The_list_2_substring = The_list_2_substring.Remove(0, 1);
                    The_list_2_substring += stringggg_5;
                }
                else if (i == 15)
                {
                    stringggg_5 += The_list_1_substring[0];
                    The_list_1_substring = The_list_1_substring.Remove(0, 1);
                    The_list_1_substring += stringggg_5;
                    stringggg_5 = "";
                    stringggg_5 += The_list_2_substring[0];
                    The_list_2_substring = The_list_2_substring.Remove(0, 1);
                    The_list_2_substring += stringggg_5;
                }
                else
                {
                    stringggg_5 += The_list_1_substring.Substring(0, 2);
                    The_list_1_substring = The_list_1_substring.Remove(0, 2);
                    The_list_1_substring += stringggg_5;
                    stringggg_5 = "";
                    stringggg_5 += The_list_2_substring.Substring(0, 2);
                    The_list_2_substring = The_list_2_substring.Remove(0, 2);
                    The_list_2_substring += stringggg_5;
                }
            }

           

            List<string> keys = new List<string>();
            for (int i = 0; i < The_List_2.Count; i++)
            {
                string s = The_List_1[i] + The_List_2[i]; 
                keys.Add(s);
            }

            
            List<string> nkeys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                The_Temp = "";
                stringggg_5 = "";
                stringggg_5 = keys[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    
                        The_Temp += stringggg_5[Array_2[i, j] - 1];
                    
                }
                nkeys.Add(The_Temp);
            }


            
            string ip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ip = ip + The_plaaain[array_5[i, j] - 1];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = ip.Substring(0, 32);
            string r = ip.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebit = "";
            string exork = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";

            for (int i = 0; i < 16; i++)
            {
                L.Add(r);
                exork = "";
                ebit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        ebit += r[array_4[j, k] - 1];
                    }
                }

                for (int g = 0; g < ebit.Length; g++)
                {
                    exork = exork + (nkeys[i][g] ^ ebit[g]).ToString();
                }

                for (int z = 0; z < exork.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exork.Length)
                            t = t + exork[y];
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

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);

                    switch (s)
                    {
                        case 0:
                            sb = var_1[row, col];
                            break;
                        case 1:
                            sb = var_2[row, col];
                            break;
                        case 2:
                            sb = var_3[row, col];
                            break;
                        case 3:
                            sb = var_4[row, col];
                            break;
                        case 4:
                            sb = var_5[row, col];
                            break;
                        case 5:
                            sb = var_6[row, col]; 
                            break;
                        case 6:
                            sb = var_7[row, col];
                            break;
                        case 7:
                            sb = var_8[row, col];
                            break;
                        default:
                            sb = sb;
                            break; 
                    }

                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                }

                x = "";
                h = "";

                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp += tsb[Array_3[k, j] - 1];
                    }
                }

                for (int k = 0; k < pp.Length; k++)
                {
                    lf +=  (pp[k] ^ l[k]).ToString();
                }

                r = lf;
                l = L[i + 1];
                R.Add(r);
            }
            string r16l16 = R[16] + L[16];
            string ciphertxt = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt = ciphertxt + r16l16[array_6[i, j] - 1];
                }
            }
             

            return "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X");
        }
    }
}