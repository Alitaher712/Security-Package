using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>

    public class AES : CryptographicTechnique
    {
        byte[,] The_SBox = new byte[16, 16]
       {
      {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
      {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
      {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
      {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
      {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
      {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
      {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
      {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
      {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
      {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
      {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
      {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
      {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
      {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
      {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
      {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
       };

        byte[,] The_Rcon_matriex = new byte[4, 10]
        {
        {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
        };


        private byte[,] inverseThe_SBox = new byte[16, 16]
        {
      {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
      {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
      {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
      {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
      {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
      {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
      {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
      {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
      {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
      {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
      {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
      {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
      {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
      {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
      {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
      {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
        };

        public static void Fun_to_swap<var_0>(ref var_0 tempp_1, ref var_0 tempp_2)
        {
            var_0 variable_1;
            variable_1 = tempp_1;
            tempp_1 = tempp_2;
            tempp_2 = variable_1;
        }
        public static byte[,] inverseFun_Shift_Rows(byte[,] temp)
        {
            Fun_to_swap(ref temp[1, 2], ref temp[1, 3]);
            Fun_to_swap(ref temp[1, 1], ref temp[1, 2]);
            Fun_to_swap(ref temp[1, 0], ref temp[1, 1]);

            Fun_to_swap(ref temp[2, 0], ref temp[2, 2]);
            Fun_to_swap(ref temp[2, 1], ref temp[2, 3]);

            Fun_to_swap(ref temp[3, 0], ref temp[3, 1]);
            Fun_to_swap(ref temp[3, 1], ref temp[3, 2]);
            Fun_to_swap(ref temp[3, 2], ref temp[3, 3]);


            byte[,] The_Returned_value;
            The_Returned_value = temp;
            return The_Returned_value;
        }

        static byte[] Matriex_muliply(byte Item)
        {
            byte[] index;
            index = new byte[8];
            index[0] = Item;
            index[1] = Item >= 128 ? byte.Parse(((byte)(Item << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(Item << 1)).ToString());
            index[2] = index[1] >= 128 ? byte.Parse(((byte)(index[1] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[1] << 1)).ToString());
            index[3] = index[2] >= 128 ? byte.Parse(((byte)(index[2] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[2] << 1)).ToString());
            index[4] = index[3] >= 128 ? byte.Parse(((byte)(index[3] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[3] << 1)).ToString());
            index[5] = index[4] >= 128 ? byte.Parse(((byte)(index[4] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[4] << 1)).ToString());
            index[6] = index[5] >= 128 ? byte.Parse(((byte)(index[5] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[5] << 1)).ToString());
            index[7] = index[6] >= 128 ? byte.Parse(((byte)(index[6] << 1) ^ (0x1b)).ToString()) : byte.Parse(((byte)(index[6] << 1)).ToString());
            byte[] The_Returned_value;
            The_Returned_value = index;
            return The_Returned_value;

        }
        static byte[,] inverseMixCols(byte[,] state)
        {
            byte[,] INVMix = new byte[4, 4] {
                {0X0E,0X0B, 0X0D,0X09},
                { 0X09,0X0E,0X0B,0X0D},
                { 0X0D,0X09,0X0E,0X0B},
                { 0X0B,0X0D,0X09,0X0E}
        };

            // BitArray bits = new BitArray(BitConverter.GetBytes(second).ToArray());

            byte[,] The_New_Matriex = new byte[4, 4];

            int index = 0;
            int four;
            four = 4;
            int i;
            i = 0;
            do

            {
                int j;
                j = 0;
                do

                {
                    byte The_Answer;
                    The_Answer = 0x00;


                    four = 4;
                    int var_1;
                    var_1 = 0;
                    do

                    {
                        byte tmp;
                        tmp = 0x00;
                        byte[] The_Byte_0 = new byte[8];
                        The_Byte_0 = Matriex_muliply(state[var_1, j]);
                        byte t = INVMix[i, var_1];
                        BitArray bitarray = new BitArray(BitConverter.GetBytes(t).ToArray());

                        int var_2;
                        var_2 = 0;
                        do

                        {
                            if (bitarray[var_2])
                            {
                                tmp = (byte)((int)tmp ^ (int)The_Byte_0[var_2]);
                            }

                            var_2++;
                        } while (var_2 < four);

                        The_Answer = (byte)((int)The_Answer ^ (int)tmp);

                        var_1++;
                    } while (var_1 < four);



                    The_New_Matriex[i, j] = The_Answer;
                    j++;
                } while (j < four);
                i++;
            } while (i < four);

           
            
            byte[,] The_Returned_value;
            The_Returned_value = The_New_Matriex;
            return The_Returned_value;

        }

        private byte[,] inverseSubByte(byte[,] state)
        {
            byte[,] The_New_state;
            The_New_state = new byte[4, 4];
            int i = 0;
            bool falg_0;
            falg_0 = false;
            switch (falg_0)
            {
                case false:
                    {
                        do
                        {

                            int j;
                            j = 0;
                            do
                            {
                                The_New_state[i, j] = inverseThe_SBox[state[i, j] >> 4, state[i, j] & 0x0f]; j++;
                            } while (j < 4);
                            i++;
                        } while (i < 4);
                        break;
                    }
                case true:
                    {
                        int j = 0;
                        do
                        {
                            The_New_state[i, j] = inverseThe_SBox[state[i, j] >> 4, state[i, j] & 0x0f]; j++;
                        } while (j < 4);
                        break;
                    }
                default:
                    {
                        break;
                    }


            }


            byte[,] The_Returned_value;
            The_Returned_value = The_New_state;
            return The_Returned_value;


        }


        // fahd
        byte[,,] The_Keeys = new byte[10, 4, 4];
        byte[,] Fun_Bring_The_Key(int The_Round_Key)
        {

            byte[,] The_New_Matriex;
            The_New_Matriex = new byte[4, 4];

            int var_19 = 0;
            int flag_1 = 10;
            int falg_2 = 9;
            int subtract_0 = flag_1 - falg_2;

            if (subtract_0 != 1)
            {
                int var_18;
                for (var_18 = 0; var_18 < 4; ++var_18)
                {
                    The_New_Matriex[var_19, var_18] = The_Keeys[The_Round_Key, var_19, var_18];
                }
            }
            else
            {
                do

                {
                    int var_18;
                    var_18 = 0;
                    for (var_18 = 0; var_18 < 4; ++var_18)
                    {
                        The_New_Matriex[var_19, var_18] = The_Keeys[The_Round_Key, var_19, var_18];
                    }

                    var_19++;
                } while (var_19 < 4);
            }


            byte[,] The_Returned_value;
            The_Returned_value = The_New_Matriex;
            return The_Returned_value;


        }


        public override string Decrypt(string cipherText, string key)
        {
            byte[,] The_cipherText_Matriex;
            The_cipherText_Matriex = StringToMatrixOfBytes(cipherText);
            byte[,] The_Keey;
            The_Keey = StringToMatrixOfBytes(key);
            int var_1 = 0;
            do
            // for (int i = 0; i < 4; i++)
            {
                int var_2;
                var_2 = 0;
                do
                /// for (int j = 0; j < 4; j++)
                {


                    for (int var_3 = 0; var_3 < 4; ++var_3)
                    {
                        The_Keeys[var_1, var_3, var_2] = The_Keey[var_3, var_2];
                    }
                    var_2++;

                }
                while (var_2 < 4);
                byte[,] condition_0;
                condition_0 = GenerateRoundKey(The_Keey, var_1 + 1);
                The_Keey = condition_0;
                var_1++;
            }
            while (var_1 < 10);
            byte[,] Add_Roundkey = AddRoundkey(The_cipherText_Matriex, The_Keey);
            The_cipherText_Matriex = Add_Roundkey;

            //the Rounds from 1 to 9

            // for (int i = 9; i >= 1; --i)
            byte[,] Inverse_The_Inverse;
            byte[,] Inverse_The_SubByte;
            byte[,] Add_Round_key;
            byte[,] The_Invers_mix;
            int i = 9;
            do
            {
                The_Keey = Fun_Bring_The_Key(i);
                Inverse_The_Inverse = inverseFun_Shift_Rows(The_cipherText_Matriex);
                Inverse_The_SubByte = inverseSubByte(Inverse_The_Inverse);
                Add_Round_key = AddRoundkey(Inverse_The_SubByte, The_Keey);
                The_Invers_mix = inverseMixCols(Add_Round_key);
                The_cipherText_Matriex = The_Invers_mix;
                i--;
            } while (i >= 1);
            //Round 10
            The_Keey = Fun_Bring_The_Key(0);
            // Inverse_The_Inverse= inverseFun_Shift_Rows(The_cipherText_Matriex); 

            Inverse_The_Inverse = inverseFun_Shift_Rows(The_cipherText_Matriex);
            Inverse_The_SubByte = inverseSubByte(Inverse_The_Inverse);
            Add_Round_key = AddRoundkey(Inverse_The_SubByte, The_Keey);
            // The_Invers_mix = inverseMixCols(Add_Round_key);
            The_cipherText_Matriex = Add_Round_key;
            // The_cipherText_Matriex = AddRoundkey(inverseSubByte(inverseFun_Shift_Rows(The_cipherText_Matriex)), The_Keey);

            return MatrixOfBytesToString(The_cipherText_Matriex);

        }


        public override string Encrypt(string The_plain_Text, string key)
        {
            int x = 10;
            int y = 9;
            int sub = x - y;
            byte[,] The_New_Keey;
            The_New_Keey = StringToMatrixOfBytes(key);
            //7ot al plain text and key fy matriex
            byte[,] The_New_matriex_Plain_text;
            The_New_matriex_Plain_text = StringToMatrixOfBytes(The_plain_Text);

            byte[,] Add_Roundkey = AddRoundkey(The_New_matriex_Plain_text, The_New_Keey);
            The_New_matriex_Plain_text = Add_Roundkey;
            // first Round {0}
            if (sub == 0)
            {
                x++;
                sub = x;
                The_New_matriex_Plain_text = AddRoundkey(MixColumns(Fun_Shift_Rows(fun_Sub_Bytes(The_New_matriex_Plain_text))), The_New_Keey);

            }
            else
            {
                int varr = 1;
                do
                //  for (int i = 1; i <= 9; i++)
                {
                    byte[,] condition_0 = GenerateRoundKey(The_New_Keey, varr);
                    The_New_Keey = condition_0;
                    byte[,] sub_Bytes;
                    sub_Bytes = fun_Sub_Bytes(The_New_matriex_Plain_text);
                    byte[,] Shift_Rows = Fun_Shift_Rows(sub_Bytes);
                    byte[,] Mix_column = MixColumns(Shift_Rows);
                    byte[,] Add_Roundkkey = AddRoundkey(Mix_column, The_New_Keey);
                    The_New_matriex_Plain_text = Add_Roundkkey;
                    varr++;
                } while (varr <= 9);
            }

            // the Rounds from {1} to{ 9}

            The_New_Keey = GenerateRoundKey(The_New_Keey, 10);
            The_New_matriex_Plain_text = AddRoundkey(Fun_Shift_Rows(fun_Sub_Bytes(The_New_matriex_Plain_text)), The_New_Keey);
            //The last round
            return MatrixOfBytesToString(The_New_matriex_Plain_text);
        }
        private byte[,] fun_Sub_Bytes(byte[,] The_plaain_text)
        {
            //-condition
            byte[,] The_New_Matrieex;
            The_New_Matrieex = new byte[4, 4];
            int var_1;
            var_1 = 0;

            do
            // for (int i = 0; i < 4; i++)
            {
                int var_2;
                var_2 = 0;
                do
                /// for (int j = 0; j < 4; j++)
                {


                    The_New_Matrieex[var_1, var_2] = The_SBox[The_plaain_text[var_1, var_2] >> 4, The_plaain_text[var_1, var_2] & 0x0f];

                    var_2++;

                }
                while (var_2 < 4);
                var_1++;
            }
            while (var_1 < 4);
            byte[,] The_Retured_value;
            The_Retured_value = The_New_Matrieex;
            return The_Retured_value;
        }

        private byte[,] Fun_Shift_Rows(byte[,] The_Plain_text)
        //100%
        {
            byte[,] The_New_Matrieex;
            The_New_Matrieex = new byte[4, 4];
            int i = 0;
            int var = 10;
            int variable = 9;
            int subtract = var - variable;
            if (subtract != 0)
            {
                do
                // for (int i = 0; i < 4; i++)
                {
                    int j = 0;
                    do
                    //  for (int j = 0; j < 4; j++)
                    {
                        int summution;
                        summution = j + i;
                        if (summution < 4)
                        {
                            The_New_Matrieex[i, j] = The_Plain_text[i, summution];
                            var++;
                            variable = var;
                        }
                        //aly ma3molohom shift
                        else
                        {
                            The_New_Matrieex[i, j] = The_Plain_text[i, summution - 4];

                        }

                        j++;
                    } while (j < 4);
                    i++;
                } while (i < 4);
            }
            else
            {
                for (int vaaaar = 0; vaaaar < 4; vaaaar++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        int summution;
                        summution = j + i;
                        subtract = var + vaaaar;
                        The_New_Matrieex[i, j] = The_Plain_text[i, summution + 4];
                    }


                }

            }
            byte[,] The_Retured_value;
            The_Retured_value = The_New_Matrieex;
            return The_Retured_value;


        }


        byte[,] The_mix_matriex = new byte[4, 4] {
        {0x02,0x03,0x01,0x01},
        {0x01,0x02,0x03,0x01},
        {0x01,0x01,0x02,0x03},
        {0x03,0x01,0x01,0x02}};
        private byte[,] MixColumns(byte[,] The_Plain_text)
        {
            byte[,] The_New_Matrieex;
            The_New_Matrieex = new byte[4, 4];
            int var_1;
            var_1 = 0;
            do
            //  for (int i = 0; i < 4; i++)

            {
                int var_2;
                var_2 = 0;
                do
                //  for (int j = 0; j < 4; j++)
                {
                    //fahd(res)
                    byte Res = 0x00;
                    int k;
                    k = 0;
                    do
                    // for (int k = 0; k < 4; k++)
                    {
                        byte variable;
                        byte n = 0x03;
                        byte n2 = 0x80;
                        byte n3 = 0x02;
                        byte n4 = 0x1b;


                        variable = The_Plain_text[k, var_2];

                        switch (The_mix_matriex[var_1, k])
                        {

                            case 0x03:
                                {
                                    variable = (byte)(The_Plain_text[k, var_2] << 1);
                                    byte plain_of_text;
                                    plain_of_text = (byte)(The_Plain_text[k, var_2] & n2);

                                    if (plain_of_text == n2)
                                    {
                                        byte condition_1;
                                        condition_1 = (byte)((int)variable ^ (int)(n4));
                                        variable = condition_1;
                                    }
                                    int x_0r_1;
                                    x_0r_1 = (int)variable;
                                    int x_0r_2;
                                    x_0r_2 = (int)The_Plain_text[k, var_2];
                                    variable = (byte)(x_0r_1 ^ x_0r_2);
                                    break;
                                }
                            case 0x02:
                                {
                                    byte condition_2;
                                    condition_2 = (byte)(The_Plain_text[k, var_2] << 1);
                                    variable = condition_2;
                                    byte conditio_3 = (byte)(The_Plain_text[k, var_2] & n2);
                                    if (conditio_3 == n2)
                                    {
                                        byte cc = (byte)((int)variable ^ (int)(n4));
                                        variable = cc;
                                    }

                                    break;
                                }
                            case 0x01:
                                {
                                    byte condition = The_Plain_text[k, var_2];
                                    variable = condition;
                                    break;
                                }

                        }
                        byte The_result = (byte)((int)Res ^ (int)variable);
                        Res = The_result;
                        k++;
                    }
                    while (k < 4);
                    //  byte The_result_2 = The_New_Matrieex[var_1, var_2];
                    The_New_Matrieex[var_1, var_2] = Res;
                    var_2++;
                }
                while (var_2 < 4);
                var_1++;
            }
            while (var_1 < 4);
            byte[,] The_Retured_value;
            The_Retured_value = The_New_Matrieex;
            return The_Retured_value;

        }



        private byte[,] GenerateRoundKey(byte[,] The_Keey, int Round_of_key)

        {
            byte[,] The_New_Matriex = new byte[4, 4];
            The_New_Matriex[0, 0] = The_SBox[The_Keey[1, 3] >> 4, The_Keey[1, 3] & 0x0f];
            The_New_Matriex[1, 0] = The_SBox[The_Keey[2, 3] >> 4, The_Keey[2, 3] & 0x0f];
            The_New_Matriex[2, 0] = The_SBox[The_Keey[3, 3] >> 4, The_Keey[3, 3] & 0x0f];
            The_New_Matriex[3, 0] = The_SBox[The_Keey[0, 3] >> 4, The_Keey[0, 3] & 0x0f];
            int i = 0;
            do

            {
                The_New_Matriex[i, 0] = (byte)((int)The_New_Matriex[i, 0] ^ (int)The_Rcon_matriex[i, Round_of_key - 1]);
                The_New_Matriex[i, 0] = (byte)((int)The_New_Matriex[i, 0] ^ (int)The_Keey[i, 0]);
                i++;
            } while (i < 4);
            int iii = 1;
            int x = 5;
            int y = 6;
            int var = y - x;
            if (var == 0)
            {
                for (int jjjj = 0; jjjj < 4; jjjj++)
                {
                    The_New_Matriex[jjjj, iii] = (byte)((int)The_New_Matriex[jjjj, iii - 2] ^ (int)The_Keey[jjjj, iii]);
                }
            }
            else
            {
                do


                {
                    bool falg_1;
                    falg_1 = true;
                    if (falg_1 == false)
                    {
                        falg_1 = false;
                        break;
                    }
                    else
                    {
                        for (int jjjj = 0; jjjj < 4; jjjj++)
                        {
                            byte condition;
                            int num;
                            num = iii - 1;
                            int numm = (int)The_Keey[jjjj, iii];
                            condition = (byte)((int)The_New_Matriex[jjjj, num] ^ numm);
                            The_New_Matriex[jjjj, iii] = condition;
                        }
                        iii++;
                    }
                }
                while (iii < 4);
            }
            byte[,] The_Retured_value;
            The_Retured_value = The_New_Matriex;
            return The_Retured_value;

        }

        private byte[,] AddRoundkey(byte[,] The_Plain_text, byte[,] The_Keey)
        {
            //100%
            byte[,] The_New_Matrieex;
            The_New_Matrieex = new byte[4, 4];
            int x = 6;
            int y = 5;
            int sub = x - y;
            if (sub == 0)
            {
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {

                        The_New_Matrieex[i, j] = (byte)((int)The_Plain_text[i, j] ^ (int)The_Keey[i, j]);
                    }
                }
            }
            else
            {
                int i = 0;
                do

                {
                    int j = 0;
                    do

                    {

                        byte condition_0;
                        condition_0 = (byte)((int)The_Plain_text[i, j] ^ (int)The_Keey[i, j]);
                        The_New_Matrieex[i, j] = condition_0;
                        j++;
                    }
                    while (j < 4);
                    i++;
                }
                while (i < 4);
            }

            byte[,] The_Retured_value;
            The_Retured_value = The_New_Matrieex;
            return The_New_Matrieex;

        }

        private byte[,] StringToMatrixOfBytes(string HexStr)
        {
            string converted;
            int n = HexStr.Length;
            int n2;
            n2 = n - 2;
            converted = HexStr.Substring(2, n2);
            byte[] Temp = Enumerable.Range(0, converted.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(converted.Substring(x, 2), 16)).ToArray();
            byte[,] The_new_matriex;
            The_new_matriex = new byte[4, 4];
            int var;
            var= 0;
            int four;
            four = 4;
            int i;
            i = 0;
            do

            {
                int j;
                j = 0;
                do

                {
                    The_new_matriex[j, i] = Temp[var];
                    var++;
                    j++;
                } while (j < four);
                i++;
            } while (i < four);


            byte[,] The_Retured_value;
            The_Retured_value = The_new_matriex;
            return The_new_matriex;

        }
        private string MatrixOfBytesToString(byte[,] Mbytes)
        {
            int sixteen;
            sixteen = 16;
            byte[] The_New_Matriexx;
            The_New_Matriexx = new byte[sixteen];
            int index = 0;
            int four;
            four = 4;
            int i;
            i = 0;
            do

            {
                int j;
                j = 0;
                do

                {
                    The_New_Matriexx[index] = Mbytes[j, i];
                    index++;
                    j++;
                } while (j < four);
                i++;
            } while (i < four);

            StringBuilder convertted;
            int lenght = The_New_Matriexx.Length;
            int converted_lenght = lenght * 2;
            convertted = new StringBuilder(converted_lenght);
            int i1;
            for (i1 = 0; i1 < The_New_Matriexx.Length; i1++)
            {
                byte indexxx = The_New_Matriexx[i1];
                convertted.AppendFormat("{0:x2}", indexxx);
            }
            string n;
            n = convertted.ToString();
            return "0x" + n;
        }
    }
}