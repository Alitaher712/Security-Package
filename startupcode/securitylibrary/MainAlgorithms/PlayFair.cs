using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            //   throw new NotImplementedException();
         cipherText =   cipherText.ToLower(); 
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            string PT= "";
            char[,] arrMatrix = new char[5, 5];
            string MatrixString = "";
            int keyLength = key.Length;
            bool InsertI = true;
            for (int i = 0; i < keyLength; i++)
            {
                if ((key[i] == 'j' || key[i] == 'i') && MatrixString.Contains('i')) continue;
                if (!MatrixString.Contains(key[i]) && key[i] == 'j' && InsertI)
                {
                    MatrixString += 'i';
                    InsertI = false;
                    continue;
                }
                else if (!MatrixString.Contains(key[i]) && key[i] != 'j')
                    MatrixString += key[i];
                else
                    continue;
            }
            for (int i = 0; i < alphabet.Length; i++)
            {
                if (!MatrixString.Contains(alphabet[i]))
                    MatrixString += alphabet[i];
                else
                    continue;
            }
            int cnt = 0;
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                {
                    arrMatrix[i, j] = MatrixString[cnt];
                    cnt++;
                }

            int CTLength = cipherText.Length;
            for (int i = 0; i < CTLength; i += 2)
            {
                char c1 = cipherText[i], c2 = cipherText[i + 1];
                int idxC1I = 0, idxC1J = 0, idxC2I = 0, idxC2J = 0;
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (arrMatrix[j, k] == c1)
                        {
                            idxC1I = j; idxC1J = k;
                        }
                        else if (arrMatrix[j, k] == c2)
                        {
                            idxC2I = j; idxC2J = k;
                        }
                    }
                }
                if (idxC1J == idxC2J)
                {
                    PT += arrMatrix[((idxC1I + 4) % 5 ), idxC1J];
                    PT += arrMatrix[((idxC2I + 4) % 5) , idxC2J];
                }
                else if (idxC1I == idxC2I)
                {
                    PT += arrMatrix[idxC1I , ((idxC1J + 4) % 5)];
                    PT += arrMatrix[idxC2I , ((idxC2J + 4) % 5)];
                }
                else
                {
                    PT += arrMatrix[idxC1I , idxC2J];
                    PT += arrMatrix[idxC2I , idxC1J];
                }

            }


            string ans = PT;
            if (PT[PT.Length - 1] == 'x')
            {
                ans = ans.Remove(PT.Length - 1);
            }
            string FPT = "";
            int w = 0;
            for (int i = 0; i < ans.Length; i++)
            {
                if (PT[i] == 'x')
                {
                    if (PT[i - 1] == PT[i + 1])
                    {
                        if (i + w < ans.Length && (i - 1) % 2 == 0)
                        {
                            ans = ans.Remove(i + w, 1);
                            w--;
                        }
                    }
                }
            }

            FPT += ans;

            Console.WriteLine(FPT);
      
            return FPT;
            
        }
        
       
        public string Encrypt(string plainText, string key)
        {
            //            throw new NotImplementedException();
            plainText = plainText.ToLower();
            string Ch = ""; 
            char[,] arrMatrix = new char [5, 5];
            string MatrixString = ""; 
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            int keyLength = key.Length;
            bool InsertI = true; 
            for (int i = 0; i < keyLength; i++) {
                if ( ( key[i] == 'j' || key[i] == 'i') &&  MatrixString.Contains('i')) continue; 
                if (!MatrixString.Contains(key[i]) && key[i] == 'j' && InsertI)
                {
                    MatrixString += 'i';
                    InsertI = false;
                    continue; 
                }
                else if (!MatrixString.Contains(key[i]) && key[i] != 'j') 
                    MatrixString += key[i];
                else
                    continue; 
            }
            for(int i = 0; i< alphabet.Length; i++)
            {
                if (!MatrixString.Contains(alphabet[i]))
                    MatrixString += alphabet[i];
                else
                    continue; 
            }
            int cnt = 0 ;
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                {
                    arrMatrix[i ,j] = MatrixString[cnt];
                    cnt++;
                }

       /*     Console.WriteLine(MatrixString);
            for (int kk = 0; kk < 5; kk++)
                for (int jj = 0; jj < 5; jj++)
                    Console.WriteLine(arrMatrix[kk, jj] + " ") ; */ 

           for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Substring(0, i + 1) + 'x' + plainText.Substring(i + 1);
                }

            }
           if (plainText.Length % 2 == 1) plainText += 'x'; 
            int PTLength = plainText.Length;
            for (int i = 0; i < PTLength; i += 2)
            {
                char c1 = plainText[i], c2 = plainText[i + 1];
                int idxC1I  = 0 , idxC1J = 0 , idxC2I = 0 , idxC2J = 0 ;
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (arrMatrix[j, k] == c1)
                        {
                            idxC1I = j; idxC1J = k;
                        }
                        else if (arrMatrix[j, k] == c2)
                        {
                            idxC2I = j; idxC2J = k;
                        }
                    }
                }

                if (idxC1I == idxC2I)  
                {
                    Ch += arrMatrix[idxC1I, ((idxC1J + 1) % 5)];
                    Ch += arrMatrix[idxC2I, ((idxC2J + 1) % 5)];
                }
                else if (idxC1J == idxC2J) 
                {
                    Ch += arrMatrix[((idxC1I + 1) % 5 ), idxC1J];
                    Ch += arrMatrix[((idxC2I + 1) % 5) , idxC2J];
                    
                }
                else
                {
                    Ch += arrMatrix[idxC1I, idxC2J];
                    Ch += arrMatrix[idxC2I, idxC1J];
                }
               

            }
            Console.WriteLine(Ch.ToUpper());
           Console.WriteLine("\n\n");
            return Ch.ToUpper();


        }
        
    }
}
