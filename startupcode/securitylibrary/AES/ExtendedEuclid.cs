using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //  throw new NotImplementedException();
            int[] Q = new int[baseN];
            int[] A1 = new int[baseN];
            int[] A2 = new int[baseN];
            int[] A3 = new int[baseN];
            int[] B1 = new int[baseN];
            int[] B2 = new int[baseN];
            int[] B3 = new int[baseN];
            A1[0] = 1; A2[0] = 0; A3[0] = baseN;
            B1[0] = 0; B2[0] = 1; B3[0] = number;
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
                    B2[i] = B2[i] + baseN;
                    B2[i] %= baseN;
                }
                else
                {
                    B2[i] %= baseN;
                }
                Mul_inverse = B2[i];
            }
            if (B3[i] == 0)
            {
                Mul_inverse = No_inverse;

            }
            return Mul_inverse;
        }
    }
}