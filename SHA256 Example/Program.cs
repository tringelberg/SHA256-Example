using SHA256_Example.Classes;

namespace SHA256_Example
{
internal class Program
    {
        static void Main(string[] args)
        {
            MySHA256 sha256 = new();

            Console.WriteLine("SHA256-HashSum Example");
            Console.WriteLine("Please enter the text to create hash from.");
            Console.WriteLine("");

            while (true)
            {
                string? buffer;
                Console.Write("> ");

                buffer = Console.ReadLine();

                using MemoryStream ms = new();
                using StreamWriter sw = new(ms);

                sw.Write(buffer);
                sw.Flush();
                ms.Position = 0;

                Console.WriteLine($"{sha256.ComputeHash(ms)}");
            }
        }
    }
}