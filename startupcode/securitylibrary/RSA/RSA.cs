using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.DiffieHellman;
using SecurityLibrary.AES;
namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int num = p * q;
            int E = e;
            int result = 1;
            int Eular = (p - 1) * (q - 1);
            int Remainder;
            if (E < Eular && E > 0)
            {
                while (E != 0)
                {
                    Remainder = Eular % e;
                    Eular = E;
                    E = Remainder;
                }
            }
            for (int i = 0; i < e; i++)
            {
                result *= M;
                result %= num;
            }
            return result;
        }
        public int Decrypt(int p, int q, int C, int e)
        {
            int num = p * q;
            int E = e;
            int result = 1;
            int Eular = (p - 1) * (q - 1);
            int[] Q = new int[Eular]; int[] A1 = new int[Eular]; int[] A2 = new int[Eular]; int[] A3 = new int[Eular];
            int[] B1 = new int[Eular]; int[] B2 = new int[Eular]; int[] B3 = new int[Eular];
            A1[0] = 1; A2[0] = 0; A3[0] = Eular;
            B1[0] = 0; B2[0] = 1; B3[0] = e;
            int Mul_inverse = -1, No_inverse = -1;
            int i = 0;
            while (true)
            {
                Q[i + 1] = A3[i] / B3[i];
                A1[i + 1] = B1[i];
                A2[i + 1] = B2[i];
                A3[i + 1] = B3[i];
                B1[i + 1] = A1[i] - Q[i + 1] * B1[i];
                B2[i + 1] = A2[i] - Q[i + 1] * B2[i];
                B3[i + 1] = A3[i] - Q[i + 1] * B3[i];
                i++;
                if (B3[i] == 1 || B3[i] == 0)
                {
                    break;
                }
            }
            if (B3[i] == 1)
            {
                if (B2[i] < 0)
                {
                    B2[i] = B2[i] + Eular;
                    B2[i] %= Eular;
                }
                else
                {
                    B2[i] %= Eular;
                }
                Mul_inverse = B2[i];
            }
            if (B3[i] == 0)
            {
                Mul_inverse = No_inverse;

            }
            int D = Mul_inverse;
            if (E < Eular && E > 0)
            {
                int Remainder;
                while (E != 0)
                {
                    Remainder = Eular % e;
                    Eular = E;
                    E = Remainder;
                }
                for (int j = 0; j < D; j++)
                {
                    result *= C;
                    result %= num;
                }
            }
            return result;
        }
    }
}
