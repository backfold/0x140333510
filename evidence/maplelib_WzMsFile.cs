using MapleLib.WzLib;
using MapleLib.WzLib.Ut
il;
using Microsoft.VisualBasic;
using System
;
using System.Buffers;
using System.Buffers.
Binary;
using System.Collections;
using Syste
m.Collections.Generic;
using System.Diagnosti
cs;
using System.IO;
using System.IO.Pipeline
s;
using System.Linq;
using System.Runtime.In
teropServices;
using System.Security.Cryptogr
aphy;
using System.Text;
using System.Windows
.Input;

namespace MapleLib.WzLib.MSFile
{
  
  /// <summary>
    /// Represents a MapleSto
ry .ms file handler for reading, writing, and
 converting .ms files.
    // Credits: Elem81
00
    // https://github.com/Elem8100/MapleNe
crocer/blob/a1194a96ddf99e5d16225a05dfdf4d616
f1fac3f/WzComparerR2.WzLib/Ms_File.cs
    //

    /// <para>
    /// The .ms file format is
 a custom encrypted archive used to store WZ 
images. Encryption and decryption are perform
ed using the Snow2 or ChaCha20 stream cipher,
 with keys derived from the file name and a r
andomly generated salt.
    /// </para>
    /
// <para>
    /// <b>Encryption/Decryption Pr
ocess:</b>
    /// <list type="number">
    /
// <item>Random bytes and a salt are generate
d and written to the file header. The salt is
 obfuscated using XOR with the random bytes.<
/item>
    /// <item>The file name and salt a
re concatenated to form a base string for key
 derivation.</item>
    /// <item>Header and 
entry data are encrypted/decrypted using a fo
rmat-version-specific stream cipher, with key
s derived from the base string and entry-spec
ific data.</item>
    /// <item>Each entry's 
actual data is encrypted with a unique key st
ored in the entry metadata.</item>
    /// </
list>
    /// </para>
    /// <para>
    /// 
<b>How Snow2CryptoTransform is used:</b>
    
/// <list type="bullet">
    /// <item>Snow2C
ryptoTransform implements the Snow2 stream ci
pher and is used as a .NET ICryptoTransform f
or streaming encryption/decryption.</item>
  
  /// <item>Different keys are used for the h
eader, entry table, and each entry's data, ma
king each file and entry uniquely encrypted.<
/item>
    /// <item>When reading, the file i
s decrypted in stages using the appropriate k
eys to reconstruct the original data.</item>

    /// <item>When writing, new random values
 and keys are generated, and all data is encr
ypted before being written to the stream.</it
em>
    /// </list>
    /// </para>
    /// <
para>
    /// <b>Features:</b>
    /// <list 
type="bullet">
    /// <item>Reads and valida
tes .ms file headers and entries using custom
 cryptography.</item>
    /// <item>Extracts 
and loads contained images as WzImage objects
.</item>
    /// <item>Saves new or modified 
.ms files with correct structure and encrypti
on.</item>
    /// <item>Implements IDisposab
le for proper stream management.</item>
    /
// </list>
    /// </para>
    /// </summary>

    /// 
    public class WzMsFile : IDispos
able
    {
        private const int Version2
MinimumEntryBytes = sizeof(int) + (7 * sizeof
(int)) + WzMsConstants.EntryKeySize;
        
private const int Version4MinimumEntryBytes =
 (sizeof(int) * 10) + WzMsConstants.EntryKeyS
ize;
        private const int MaxEntryCount 
= 100_000;
        private const int MaxEntry
NameLength = 1_048_576;

        private read
only string originalFileName;
        private
 readonly string msFilePath;
        private 
static readonly byte[] ChaCha20KeyObscure =
 
       [
            0x7B, 0x2F, 0x35, 0x48, 
0x43, 0x95, 0x02, 0xB9,
            0xAE, 0x9
1, 0xA6, 0xE1, 0xD8, 0xD6, 0x24, 0xB4,
      
      0x33, 0x10, 0x1D, 0x3D, 0xC1, 0xBB, 0xC
6, 0xF4,
            0xA5, 0xFE, 0xB3, 0x69, 
0x6B, 0x56, 0xE4, 0x75
        ];

        //
/ <summary>
        /// Constructor
        /
// </summary>
        /// <param name="baseSt
ream"></param>
        /// <param name="origi
nalFileName">i.e Mob_00000.ms</param>
       
 /// <param name="msFilePath">Full path to .m
s file</param>
        /// <param name="leave
Open"></param>
        /// <param name="isSav
ingFile">Set to true if creating a new .ms fi
le for saving</param>
        /// <exception 
cref="ArgumentNullException"></exception>
   
     public WzMsFile(Stream baseStream, strin
g originalFileName, string msFilePath, bool l
eaveOpen = false, bool isSavingFile = false)

        {
            ArgumentNullException.T
hrowIfNull(baseStream);
            ArgumentN
ullException.ThrowIfNull(originalFileName);
 
           if (string.IsNullOrWhiteSpace(msFi
lePath))
                throw new ArgumentEx
ception("Path cannot be null or empty.", name
of(msFilePath));

            this.BaseStream
 = baseStream;
            this.leaveOpen = l
eaveOpen;
            this.msFilePath = msFil
ePath;
            this.originalFileName = or
iginalFileName;
            this.Entries = []
;

            if (!isSavingFile)
           
     this.ReadHeader(originalFileName);
     
   }

        public Stream BaseStream { get;
 private set; }
        public WzMsHeader Hea
der { get; private set; }
        public List
<WzMsEntry> Entries { get; private set; }
   
     private bool leaveOpen;

        #region
 Common
        /// <summary>
        /// Der
ives the Snow2 encryption key from the file n
ame and salt.
        /// </summary>
        
/// <param name="fileNameWithSalt">The concat
enated file name and salt.</param>
        //
/ <param name="isEntryKey">If true, uses the 
alternate derivation formula for entry encryp
tion.</param>
        private static void Der
iveSnowKey(ReadOnlySpan<char> fileNameWithSal
t, Span<byte> key, bool isEntryKey = false)
 
       {
            if (!isEntryKey)
       
     {
                // Header key: char + 
index
                for (int i = 0; i < key
.Length; i++)
                {
             
       key[i] = (byte)(fileNameWithSalt[i % f
ileNameWithSalt.Length] + i);
               
 }
            }
            else
           
 {
                // Entry key: index + mult
iplier * reversed char
                for (i
nt i = 0; i < key.Length; i++)
              
  {
                    key[i] = (byte)(i + (
i % 3 + 2) * fileNameWithSalt[fileNameWithSal
t.Length - 1 - i % fileNameWithSalt.Length]);

                }
            }
        }

 
       private static void DeriveChaCha20Key(
ReadOnlySpan<char> fileNameWithSalt, Span<byt
e> key, bool isEntryKey)
        {
          
  if (!isEntryKey)
            {
            
    for (int i = 0; i < key.Length; i++)
    
            {
                    key[i] = (b
yte)(fileNameWithSalt[i % fileNameWithSalt.Le
ngth] + i);
                    key[i] ^= Cha
Cha20KeyObscure[i];
                }
       
     }
            else
            {
       
         for (int i = 0; i < key.Length; i++)

                {
                    key[i]
 = (byte)(i + (i % 3 + 2) * fileNameWithSalt[
fileNameWithSalt.Length - 1 - i % fileNameWit
hSalt.Length]);
                    key[i] ^=
 ChaCha20KeyObscure[i];
                }
   
         }
        }
        #endregion

    
    #region Read file
        private void Va
lidateVersion2EntryCount(int entryCount, long
 entryStartPosition)
        {
            if
 (entryCount < 0 || entryCount > MaxEntryCoun
t)
                throw new InvalidDataExcep
tion($"Invalid version {WzMsConstants.Version
2} entry count: {entryCount}");
            i
f (entryStartPosition < 0 || entryStartPositi
on > BaseStream.Length)
                throw
 new InvalidDataException($"Invalid version {
WzMsConstants.Version2} entry start position:
 {entryStartPosition}");

            long av
ailable = BaseStream.Length - entryStartPosit
ion;
            if (entryCount > available /
 Version2MinimumEntryBytes)
                t
hrow new InvalidDataException($"Version {WzMs
Constants.Version2} entry table exceeds the c
ontaining stream.");
        }

        priva
te void ValidateEntryDataBounds(WzMsEntry ent
ry)
        {
            if (entry == null)

                throw new InvalidDataExceptio
n("MS entry is null.");
            if (entry
.Size < 0 || entry.SizeAligned < 0 || entry.S
izeAligned < entry.Size)
                thro
w new InvalidDataException($"Invalid MS entry
 size for '{entry.Name}'.");

            if 
(entry.Data != null)
            {
          
      if (entry.Size > entry.Data.Length)
   
                 throw new InvalidDataExcepti
on($"MS entry '{entry.Name}' size exceeds its
 in-memory data.");
                return;
 
           }

            if (entry.StartPos 
< 0 || entry.StartPos > BaseStream.Length)
  
              throw new InvalidDataException(
$"MS entry '{entry.Name}' offset is outside t
he containing stream.");

            long re
maining = BaseStream.Length - entry.StartPos;

            if (entry.Size > remaining || en
try.SizeAligned > remaining)
                
throw new InvalidDataException($"MS entry '{e
ntry.Name}' exceeds the containing stream.");

        }

        /// <summary>
        ///
 Reads and parses the .ms file header from th
e provided stream.
        /// </summary>
   
     /// <param name="fullFileName"></param>

        /// <exception cref="Exception"></exc
eption>
        private void ReadHeader(strin
g fullFileName)
        {
            Excepti
on version2Exception;
            try
       
     {
                ReadHeaderVersion2(ful
lFileName);
                return;
         
   }
            catch (Exception ex)
       
     {
                version2Exception = ex
;
            }

            try
            
{
                ReadHeaderVersion4(fullFile
Name);
            }
            catch (Excep
tion version4Exception)
            {
       
         throw new InvalidDataException(
    
                $"Unable to read MS file head
er as version {WzMsConstants.Version2} or {Wz
MsConstants.Version4}. " +
                  
  $"Version {WzMsConstants.Version2}: {versio
n2Exception.Message}; " +
                   
 $"Version {WzMsConstants.Version4}: {version
4Exception.Message}",
                    ver
sion4Exception);
            }
        }

   
     private void ReadHeaderVersion2(string f
ullFileName)
        {
            string fil
eName = Path.GetFileName(fullFileName).ToLowe
r();
            this.BaseStream.Position = 0
;
            using var bReader = new BinaryR
eader(this.BaseStream, Encoding.ASCII, true);


            int fileNameCharSum = SumChars(
fileName);
            int randByteCount = fi
leNameCharSum % WzMsConstants.RandByteMod + W
zMsConstants.RandByteOffset;
            byte
[] randBytes = bReader.ReadBytes(randByteCoun
t);
            if (randBytes.Length != randB
yteCount || randBytes.Length == 0)
          
      throw new EndOfStreamException();

    
        int hashedSaltLen = bReader.ReadInt32
();
            int saltLen = (byte)hashedSal
tLen ^ randBytes[0];
            if (saltLen 
> randBytes.Length)
                throw new
 InvalidDataException($"Invalid version {WzMs
Constants.Version2} salt length: {saltLen}");


            if ((long)saltLen * 2 > BaseStr
eam.Length - BaseStream.Position)
           
     throw new EndOfStreamException();
      
      byte[] saltBytes = bReader.ReadBytes(sa
ltLen * 2);
            if (saltBytes.Length 
!= saltLen * 2)
                throw new End
OfStreamException();
            char[] saltC
hars = new char[saltLen];
            for (in
t i = 0; i < saltLen; i++)
            {
    
            saltChars[i] = (char)(randBytes[i
] ^ saltBytes[i * 2]);
            }
        
    string saltStr = new(saltChars);

       
     string fileNameWithSalt = fileName + sal
tStr;
            Span<byte> snowCipherKey = 
stackalloc byte[WzMsConstants.SnowKeyLength];

            DeriveSnowKey(fileNameWithSalt, 
snowCipherKey, false);

            long head
erStartPos = this.BaseStream.Position;
      
      using var snowCipher = new Snow2CryptoT
ransform(snowCipherKey, null, false);
       
     using var snowDecoderStream = new Crypto
Stream(this.BaseStream, snowCipher, CryptoStr
eamMode.Read, true);
            using (var s
nowReader = new BinaryReader(snowDecoderStrea
m))
            {
                //byte[] la
st4 = snowReader.ReadBytes(16);
             
   //Debug.WriteLine($"Last 16 bytes: {BitCon
verter.ToString(last4)}");

                v
ar (entryCount, headerHash) = ReadAndValidate
Header(snowReader, hashedSaltLen, saltBytes, 
saltLen);
                int padAmount = (fi
leNameCharSum * 3) % WzMsConstants.HeaderPadM
od + WzMsConstants.HeaderPadOffset;
         
       long entryStartPos = checked(headerSta
rtPos + 9L + padAmount);
                Vali
dateVersion2EntryCount(entryCount, entryStart
Pos);

                var header = new WzMsH
eader(fullFileName, saltStr, fileNameWithSalt
, headerHash, WzMsConstants.Version2, entryCo
unt, headerStartPos, entryStartPos);
        
        this.Header = header;
            }
 
       }

        private void ReadHeaderVers
ion4(string fullFileName)
        {
         
   string fileName = Path.GetFileName(fullFil
eName).ToLower();
            this.BaseStream
.Position = 0;
            using var bReader 
= new BinaryReader(this.BaseStream, Encoding.
ASCII, true);

            int fileNameCharSu
m = SumChars(fileName);
            int randB
yteCount = fileNameCharSum % WzMsConstants.Ra
ndByteMod + WzMsConstants.RandByteOffset;
   
         byte[] randBytes = bReader.ReadBytes
(randByteCount);
            if (randBytes.Le
ngth != randByteCount)
                throw 
new EndOfStreamException();

            for 
(int i = 0; i < randBytes.Length; i++)
      
      {
                randBytes[i] = (byte)
((sbyte)randBytes[i] >> 1);
            }

  
          byte version = (byte)(bReader.ReadB
yte() ^ randBytes[0]);
            if (versio
n != WzMsConstants.Version4)
                
throw new Exception($"Unsupported version: ex
pected {WzMsConstants.Version4}, got {version
}");

            int hashedSaltLen = bReader
.ReadInt32();
            int saltLen = ((byt
e)hashedSaltLen) ^ randBytes[0];
            
if (saltLen <= 0 || saltLen > randBytes.Lengt
h)
                throw new InvalidDataExcep
tion($"Invalid version {WzMsConstants.Version
4} salt length: {saltLen}");

            byt
e[] saltBytes = bReader.ReadBytes(saltLen * 2
);
            if (saltBytes.Length != saltLe
n * 2)
                throw new EndOfStreamE
xception();

            char[] saltChars = n
ew char[saltLen];
            for (int i = 0;
 i < saltLen; i++)
            {
            
    int a = randBytes[i] ^ saltBytes[i * 2];

                int b = ((a | 0x4B) << 1) - a
 - 75;
                saltChars[i] = (char)b
;
            }

            string saltStr =
 new(saltChars);
            string fileNameW
ithSalt = fileName + saltStr;

            Sp
an<byte> chacha20Key = stackalloc byte[WzMsCo
nstants.ChaCha20KeyLength];
            Deriv
eChaCha20Key(fileNameWithSalt, chacha20Key, f
alse);

            long headerStartPos = thi
s.BaseStream.Position;
            Span<byte>
 headerBytes = stackalloc byte[8];
          
  this.BaseStream.ReadExactly(headerBytes);
 
           Span<byte> emptyNonce = stackalloc
 byte[WzMsConstants.ChaCha20NonceLength];
   
         using (var chacha20 = new ChaCha20Cr
yptoTransform(chacha20Key, emptyNonce, 0))
  
          {
                chacha20.Transfor
mInPlace(headerBytes);
            }

       
     int headerHash = BinaryPrimitives.ReadIn
t32LittleEndian(headerBytes[..4]);
          
  int entryCount = BinaryPrimitives.ReadInt32
LittleEndian(headerBytes[4..]);
            i
f (entryCount < 0 || entryCount > MaxEntryCou
nt ||
                entryCount > (this.Base
Stream.Length - headerStartPos) / Version4Min
imumEntryBytes)
                throw new Inv
alidDataException($"Invalid version {WzMsCons
tants.Version4} entry count: {entryCount}");


            int padAmount = (fileNameCharSum
 * 3) % WzMsConstants.HeaderPadMod + 64;
    
        long entryStartPos = headerStartPos +
 8 + padAmount;
            if (entryStartPos
 < 0 || entryStartPos > this.BaseStream.Lengt
h)
                throw new InvalidDataExcep
tion($"Invalid version {WzMsConstants.Version
4} entry start position: {entryStartPos}");


            var header = new WzMsHeader(fullF
ileName, saltStr, fileNameWithSalt, headerHas
h, WzMsConstants.Version4, entryCount, header
StartPos, entryStartPos);
            this.He
ader = header;
        }

        /// <summar
y>
        /// Reads header fields and valida
tes version/hash. Returns the expected hash f
or header init.
        /// </summary>
      
  /// <param name="snowReader">The reader for
 encrypted header.</param>
        /// <param
 name="hashedSaltLen">The hashed salt length.
</param>
        /// <param name="saltBytes">
Raw salt bytes for hash calc.</param>
       
 /// <param name="saltLen">Actual salt length
.</param>
        /// <returns>A tuple contai
ning (EntryCount, CalculatedHash).</returns>

        /// <exception cref="Exception">Throw
n on version or hash mismatch.</exception>
  
      private static (int EntryCount, int Cal
culatedHash) ReadAndValidateHeader(BinaryRead
er snowReader, int hashedSaltLen, byte[] salt
Bytes, int saltLen)
        {
            int
 hash = snowReader.ReadInt32();
            b
yte version = snowReader.ReadByte();
        
    int entryCount = snowReader.ReadInt32();


            if (version != WzMsConstants.Ver
sion2)
                throw new Exception($"
Unsupported version: expected {WzMsConstants.
Version2}, got {version}");

            long
 actualHash = (long)hashedSaltLen + version +
 entryCount;
            ReadOnlySpan<ushort>
 u16SaltBytes = MemoryMarshal.Cast<byte, usho
rt>(saltBytes.AsSpan(0, saltLen * 2));
      
      for (int i = 0; i < u16SaltBytes.Length
; i++)
            {
                actualHa
sh += u16SaltBytes[i];
            }

       
     if (hash != actualHash)
                
throw new Exception($"Header hash mismatch: e
xpected {actualHash}, got {hash}");

        
    if (entryCount < 0 || entryCount > MaxEnt
ryCount)
                throw new InvalidDat
aException($"Invalid version {WzMsConstants.V
ersion2} entry count: {entryCount}");

      
      return (entryCount, checked((int)actual
Hash));
        }

        /// <summary>
    
    /// Reads all entry metadata from the und
erlying stream and populates the Entries coll
ection based on the
        /// current heade
r information.
        /// </summary>
       
 /// <remarks>This method clears the existing
 Entries collection and reloads it from the s
tream if
        /// the header indicates tha
t entries are present and have not already be
en loaded. The method updates each
        //
/ entry's start position relative to the data
 section. If the header is null, contains no 
entries, or the
        /// entries are alrea
dy loaded, the method performs no action.</re
marks>
        public void ReadEntries()
    
    {
            if (this.Header == null || 
this.Header.EntryCount == 0 || this.Header.En
tryCount == this.Entries.Count)
             
   return;
            this.Entries.Clear();

            long previousDataStart = this.Hea
der.DataStartPosition;
            try
      
      {
                if (this.Header.Versi
on == WzMsConstants.Version4)
               
 {
                    ReadEntriesVersion4();

                    return;
                
}

                ReadEntriesVersion2();
   
         }
            catch
            {
  
              this.Entries.Clear();
         
       this.Header.DataStartPosition = previo
usDataStart;
                throw;
         
   }
        }

        private void ReadEntr
iesVersion2()
        {
            int entry
Count = this.Header.EntryCount;
            V
alidateVersion2EntryCount(entryCount, this.He
ader.EntryStartPosition);
            if (thi
s.Entries.Capacity < entryCount)
            
    this.Entries.Capacity = entryCount;

    
        string fileNameWithSalt = this.Header
.FileNameWithSalt;
            Span<byte> sno
wKey = stackalloc byte[WzMsConstants.SnowKeyL
ength];
            DeriveSnowKey(fileNameWit
hSalt, snowKey, true);

            using var
 snowCipher = new Snow2CryptoTransform(snowKe
y, null, false);
            this.BaseStream.
Position = this.Header.EntryStartPosition;
  
          var snowDecoderStream = new CryptoS
tream(this.BaseStream, snowCipher, CryptoStre
amMode.Read);
            var snowReader = ne
w BinaryReader(snowDecoderStream, Encoding.Un
icode, true);

            long tableBytesCon
sumed = 0;
            for (int i = 0; i < en
tryCount; i++)
            {
                
int entryNameLen = snowReader.ReadInt32();
  
              long remainingTableBytes = Base
Stream.Length - this.Header.EntryStartPositio
n - tableBytesConsumed;
                long 
minimumBytesAfterName = (long)(entryCount - i
 - 1) * Version2MinimumEntryBytes;
          
      long maximumNameBytes = remainingTableB
ytes - Version2MinimumEntryBytes - minimumByt
esAfterName;
                if (entryNameLen
 < 0 || entryNameLen > MaxEntryNameLength ||

                    (long)entryNameLen * size
of(char) > maximumNameBytes / 1L)
           
         throw new InvalidDataException($"Inv
alid version {WzMsConstants.Version2} entry n
ame length: {entryNameLen}");

              
  char[] entryNameBuffer = ArrayPool<char>.Sh
ared.Rent(entryNameLen);
                stri
ng entryName;
                try
           
     {
                    ReadCharsExactly(s
nowReader, entryNameBuffer, entryNameLen);
  
                  entryName = new string(entr
yNameBuffer, 0, entryNameLen); // "Mob/010000
0.img"
                }
                fina
lly
                {
                    Arr
ayPool<char>.Shared.Return(entryNameBuffer);

                }

                int checkS
um = snowReader.ReadInt32();
                
int flags = snowReader.ReadInt32();
         
       int startPos = snowReader.ReadInt32();

                int size = snowReader.ReadIn
t32();
                int sizeAligned = snow
Reader.ReadInt32();
                int unk1 
= snowReader.ReadInt32();
                int
 unk2 = snowReader.ReadInt32();
             
   byte[] entryKey = snowReader.ReadBytes(WzM
sConstants.SnowKeyLength);
                if
 (entryKey.Length != WzMsConstants.SnowKeyLen
gth)
                    throw new EndOfStrea
mException();

                tableBytesCons
umed = checked(tableBytesConsumed + ((long)en
tryNameLen * sizeof(char)) + Version2MinimumE
ntryBytes);

                var entry = new 
WzMsEntry(entryName, checkSum, flags, startPo
s, size, sizeAligned, unk1, unk2, entryKey);

                // CalculatedCheckSum is set 
in constructor or via RecalculateFields, no n
eed to set here
                this.Entries.
Add(entry);
            }

            long d
ataStartPos = this.BaseStream.Position;
     
       dataStartPos = AlignToPage(dataStartPo
s); // Extracted helper
            if (dataS
tartPos > this.BaseStream.Length)
           
     throw new InvalidDataException($"Version
 {WzMsConstants.Version2} data section starts
 outside the containing stream.");
          
  this.Header.DataStartPosition = dataStartPo
s; // skip the random padding after entries


            foreach (var entry in this.Entrie
s)
            {
                if (entry.St
artPos < 0)
                    throw new Inv
alidDataException($"MS entry '{entry.Name}' h
as a negative start position.");

           
     long absoluteStart = checked(dataStartPo
s + entry.StartPos * (long)WzMsConstants.Bloc
kAlignment);
                entry.StartPos =
 absoluteStart;
                ValidateEntry
DataBounds(entry);
            }
        }

 
       private void ReadEntriesVersion4()
   
     {
            int entryCount = this.Head
er.EntryCount;
            if (entryCount < 0
 || entryCount > MaxEntryCount)
             
   throw new InvalidDataException($"Invalid v
ersion {WzMsConstants.Version4} entry count: 
{entryCount}");
            if (this.Entries.
Capacity < entryCount)
                this.E
ntries.Capacity = entryCount;

            st
ring fileNameWithSalt = this.Header.FileNameW
ithSalt;
            Span<byte> chacha20Key =
 stackalloc byte[WzMsConstants.ChaCha20KeyLen
gth];
            DeriveChaCha20Key(fileNameW
ithSalt, chacha20Key, true);

            Spa
n<byte> emptyNonce = stackalloc byte[WzMsCons
tants.ChaCha20NonceLength];
            this.
BaseStream.Position = this.Header.EntryStartP
osition;
            using var chacha20Reader
 = new ChaCha20Reader(this.BaseStream, chacha
20Key, emptyNonce, true);

            for (i
nt i = 0; i < entryCount; i++)
            {

                string entryName = chacha20Re
ader.ReadString(MaxEntryNameLength);
        
        int checkSum = chacha20Reader.ReadInt
32();
                int flags = chacha20Rea
der.ReadInt32();
                int startPos
 = chacha20Reader.ReadInt32();
              
  int size = chacha20Reader.ReadInt32();
    
            int sizeAligned = chacha20Reader.
ReadInt32();
                int unk1 = chach
a20Reader.ReadInt32();
                int un
k2 = chacha20Reader.ReadInt32();
            
    byte[] entryKey = chacha20Reader.ReadByte
s(WzMsConstants.SnowKeyLength);
             
   int unk3 = chacha20Reader.ReadInt32();
   
             int unk4 = chacha20Reader.ReadIn
t32();

                if (startPos < 0)
   
                 throw new InvalidDataExcepti
on($"MS entry '{entryName}' has a negative st
art position.");
                if (size < 0
 || sizeAligned < 0 || sizeAligned < size)
  
                  throw new InvalidDataExcept
ion($"Invalid MS entry size for '{entryName}'
.");

                var entry = new WzMsEnt
ry(entryName, checkSum, flags, startPos, size
, sizeAligned, unk1, unk2, entryKey, unk3, un
k4);
                this.Entries.Add(entry);

            }

            long dataStartPos
 = AlignToPage(this.BaseStream.Position);
   
         if (dataStartPos > this.BaseStream.L
ength)
                throw new InvalidDataE
xception($"Version {WzMsConstants.Version4} d
ata section starts outside the containing str
eam.");
            this.Header.DataStartPosi
tion = dataStartPos;

            foreach (va
r entry in this.Entries)
            {
      
          long absoluteStart = checked(dataSt
artPos + entry.StartPos * (long)WzMsConstants
.BlockAlignment);
                entry.Start
Pos = absoluteStart;
                // Versi
on 4 packs may contain an intentionally trunc
ated data section
                // (for exa
mple, metadata-only fixtures). Validate bound
s when an entry
                // is actuall
y decrypted instead of rejecting the entire t
able here.
            }
        }

        /
// <summary>
        /// Aligns position to t
he next 1024-byte page boundary.
        /// 
</summary>
        /// <param name="pos">Curr
ent position.</param>
        /// <returns>Al
igned position.</returns>
        private sta
tic long AlignToPage(long pos)
        {
    
        if (pos < 0 || pos > long.MaxValue - 
WzMsConstants.PageAlignmentMask)
            
    throw new InvalidDataException("MS data p
osition cannot be aligned safely.");
        
    return (pos + WzMsConstants.PageAlignment
Mask) & ~WzMsConstants.PageAlignmentMask;
   
     }

        private static int SumChars(R
eadOnlySpan<char> chars)
        {
          
  int sum = 0;
            for (int i = 0; i 
< chars.Length; i++)
            {
          
      sum += chars[i];
            }

       
     return sum;
        }

        private s
tatic int SumUInt16Bytes(ReadOnlySpan<byte> b
ytes)
        {
            int sum = 0;
    
        ReadOnlySpan<ushort> values = MemoryM
arshal.Cast<byte, ushort>(bytes);
           
 for (int i = 0; i < values.Length; i++)
    
        {
                sum += values[i];
 
           }

            return sum;
       
 }

        private static void ReadCharsExac
tly(BinaryReader reader, char[] buffer, int c
ount)
        {
            int offset = 0;
 
           while (offset < count)
           
 {
                int read = reader.Read(buf
fer, offset, count - offset);
               
 if (read == 0)
                    throw new
 EndOfStreamException();

                off
set += read;
            }
        }

       
 private sealed class ChaCha20Reader : IDispo
sable
        {
            private readonly 
Stream baseStream;
            private readon
ly ChaCha20CryptoTransform chacha20Cipher;
  
          private readonly bool leaveOpen;
  
          private byte[] buffer;
            
private int readOffset;

            public C
haCha20Reader(Stream baseStream, ReadOnlySpan
<byte> key, ReadOnlySpan<byte> nonce, bool le
aveOpen = false)
            {
              
  this.baseStream = baseStream;
             
   this.leaveOpen = leaveOpen;
              
  this.chacha20Cipher = new ChaCha20CryptoTra
nsform(key, nonce, 0);
                this.b
uffer = new byte[WzMsConstants.ChaCha20BlockS
ize];
                this.readOffset = this.
buffer.Length;
            }

            pub
lic byte[] ReadBytes(int count)
            {

                if (count < 0 || count > Mem
oryLimits.MAX_WZ_PAYLOAD_BYTES)
             
       throw new InvalidDataException($"Inval
id version {WzMsConstants.Version4} payload l
ength: {count}");
                byte[] resu
lt = new byte[count];
                ReadByt
es(result);
                return result;
  
          }

            public void ReadByte
s(Span<byte> destination)
            {
     
           while (destination.Length > 0)
   
             {
                    if (readOf
fset >= buffer.Length)
                    {

                        baseStream.ReadExactl
y(buffer);
                        chacha20Ci
pher.TransformInPlace(buffer);
              
          readOffset = 0;
                   
 }

                    int readCount = Math.
Min(destination.Length, buffer.Length - readO
ffset);
                    buffer.AsSpan(rea
dOffset, readCount).CopyTo(destination);
    
                destination = destination[rea
dCount..];
                    readOffset += 
readCount;
                }

               
 if (readOffset >= buffer.Length)
           
         chacha20Cipher.State[12] = 0;
      
      }

            public int ReadInt32()
 
           {
                Span<byte> value
 = stackalloc byte[4];
                ReadBy
tes(value);
                return BinaryPrim
itives.ReadInt32LittleEndian(value);
        
    }

            public string ReadString(i
nt maxLength)
            {
                i
nt length = ReadInt32();
                if (
length < 0 || length > maxLength)
           
         throw new InvalidDataException($"Inv
alid version {WzMsConstants.Version4} entry n
ame length: {length}");

                retu
rn string.Create(length, this, static (chars,
 reader) =>
                {
               
     reader.ReadBytes(MemoryMarshal.AsBytes(c
hars));
                });
            }

  
          public void Dispose()
            {

                chacha20Cipher.Dispose();
  
              Array.Clear(buffer);
          
      buffer = [];

                if (!leav
eOpen)
                    baseStream.Dispose
();
            }
        }

        /// <sum
mary>
        /// Loads a .ms file and return
s a WzFile containing all WzImages from this 
.ms file.
        /// </summary>
        /// 
<param name="msFilePath">Path to the .ms file
</param>
        /// <returns>WzFile containi
ng all images from the .ms file</returns>
   
     public WzFile LoadAsWzFile()
        {
 
           this.ReadEntries();

            W
zMapleVersion mapleVersion = WzMapleVersion.B
MS; // .ms files are always from BMS

       
     var wzFile = new WzFile(0, mapleVersion)

            {
                Name = Path.Ge
tFileName(msFilePath.Replace(".ms", ".wz")),

                path = msFilePath
           
 }; // version is always 0 as a placeholder f
or .ms files
            var wzDir = wzFile.W
zDirectory;

            wzDir.wzFile = wzFil
e;

            foreach (WzMsEntry entry in E
ntries)
            {
                byte[] 
decryptedData = DecryptDataToArray(entry);
  
              Stream decrypted = new MemorySt
ream(decryptedData, writable: false); // dont
 close this stream!
                WzBinaryR
eader reader = new(decrypted, WzTool.GetIvByM
apleVersion(mapleVersion));

                
int lastSlashIndex = entry.Name.LastIndexOf('
/'); // Mob/0100000.img
                strin
g entryImgName = (lastSlashIndex >= 0) ? entr
y.Name.Substring(lastSlashIndex + 1) : entry.
Name;

                var wzImage = new WzIm
age(entryImgName, reader);
                wz
Image.ParseImage();
                //wzImage
.Changed = true;
                wzDir.AddIma
ge(wzImage);
            }
            return
 wzFile;
        }
        #endregion

      
  #region Write file
        /// <summary>
  
      /// Initializes the header and entry li
st for the current object based on the specif
ied WzFile and
        /// initialization vec
tor.
        /// </summary>
        /// <rema
rks>This method generates a unique salt and c
onstructs a header using the original file
  
      /// name and the generated salt. The En
tries collection is populated with new entrie
s for each image in the
        /// WzFile. E
xisting entries and header data will be repla
ced.</remarks>
        /// <param name="wzFil
e">The WzFile instance containing the directo
ry and images to be processed into entries.</
param>
        /// <param name="iv">The initi
alization vector used for encrypting image da
ta when creating entries. Must not be null.</
param>
        private void CreateHeader(WzFi
le wzFile, byte[] iv)
        {
            R
andom rng = new();

            this.Entries 
= [];
            string category = Path.GetF
ileNameWithoutExtension(wzFile.Name);

      
      foreach (var wzImage in wzFile.WzDirect
ory.WzImages)
            {
                u
sing var ms = new MemoryStream();
           
     using var writer = new WzBinaryWriter(ms
, iv);
                wzImage.SaveImage(writ
er, forceReadFromData:true);
                
byte[] data = ms.ToArray();

                
string entryName = category + "/" + wzImage.N
ame;

                byte[] entryKey = new b
yte[16];
                rng.NextBytes(entryK
ey);

                var entry = new WzMsEnt
ry(entryName, 0, 0, 0, 0, 0, 0, 0, entryKey);
 // will be recalculated RecalculateFields()

                entry.Data = data;
          
      this.Entries.Add(entry);
            }


            string fileName_ = Path.GetFileN
ame(this.originalFileName).ToLower();
       
     string saltStr = GenerateSalt(WzMsConsta
nts.SaltMinLength, WzMsConstants.SaltMaxLengt
h);
            string fileNameWithSalt = fil
eName_ + saltStr;
            Header = new Wz
MsHeader(originalFileName, saltStr, fileNameW
ithSalt, 0, WzMsConstants.SupportedVersion, E
ntries.Count, 0, 0);

            this.Header
 = new WzMsHeader(this.originalFileName, salt
Str, fileNameWithSalt, 0, 2, this.Entries.Cou
nt, 0, 0);
        }

        /// <summary>
 
       /// Generates a random salt string of 
printable ASCII chars.
        /// </summary>

        /// <param name="minLen">Minimum len
gth.</param>
        /// <param name="maxLen"
>Maximum length.</param>
        /// <returns
>Salt string.</returns>
        private stati
c string GenerateSalt(int minLen, int maxLen)

        {
            int saltLen = RandomNu
mberGenerator.GetInt32(minLen, maxLen + 1);
 
           var saltChars = new char[saltLen];

            byte[] bytes = new byte[saltLen]
;

            using var rng = RandomNumberGe
nerator.Create(); // Secure RNG
            r
ng.GetBytes(bytes);

            for (int i =
 0; i < saltLen; i++)
            {
         
       saltChars[i] = (char)(WzMsConstants.As
ciiPrintableMin + (bytes[i] % (WzMsConstants.
AsciiPrintableMax - WzMsConstants.AsciiPrinta
bleMin + 1)));
            }
            retu
rn new string(saltChars);
        }

        
/// <summary>
        /// Saves the current W
zMsFile data to the underlying stream in the 
BMS format, encrypting entries and updating
 
       /// header and entry metadata as requi
red.
        /// </summary>
        /// <rema
rks>The method encrypts both the header and e
ntry data using keys derived from the file
  
      /// name and salt. After saving, the re
turned stream is reset to the beginning and r
eady for reading or writing.
        /// The 
method does not close or dispose the returned
 stream; callers are responsible for managing
 its
        /// lifetime.</remarks>
        
/// <param name="wzFile">The WzFile instance 
containing the data and entries to be saved. 
Must not be null.</param>
        /// <return
s>A Stream positioned at the beginning, conta
ining the saved and encrypted BMS file data.<
/returns>
        /// <exception cref="Invali
dOperationException">Thrown if the Header pro
perty is already present, indicating that thi
s instance has already been used for
        
/// saving. Create a new WzMsFile instance to
 perform another save operation.</exception>

        public Stream Save(WzFile wzFile)
   
     {
            byte[] iv = WzTool.GetIvBy
MapleVersion(WzMapleVersion.BMS);
           
 
            if (this.Header != null)
      
          throw new InvalidOperationException
("Cannot save when Header is already present.
 Create a new WzMsFile instance for saving.")
;

            CreateHeader(wzFile, iv);

   
         if (this.Entries == null || this.Ent
ries.Count == 0 || this.Header == null)
     
           return this.BaseStream;

         
   // Encrypt data and update entry fields
  
          // Keep encrypted data indexed by i
ts source entry. Entries with no
            
// in-memory payload are intentionally skippe
d, so a compact list
            // would shi
ft later entries and write the wrong bytes.
 
           byte[]?[] encryptedDatas = new byt
e[]?[this.Entries.Count];
            long cu
rrentBlockIndex = 0;
            for (int i =
 0; i < this.Entries.Count; i++)
            
{
                WzMsEntry entry = this.Entr
ies[i] ?? throw new InvalidDataException("MS 
entry cannot be null.");
                if (
entry.Data == null)
                    conti
nue;

                byte[] encrypted = this
.EncryptData(entry, entry.Data); // Encrypt e
ach WzImage
                int size = encryp
ted.Length;
                int sizeAligned =
 (size + WzMsConstants.PageAlignmentMask) & ~
WzMsConstants.PageAlignmentMask;
            
    entry.Size = size;
                entry.
SizeAligned = sizeAligned;
                en
try.StartPos = currentBlockIndex;
           
     currentBlockIndex += sizeAligned / 1024;

                encryptedDatas[i] = encrypte
d;

                // Recalculate checksum u
sing RecalculateFields
                entry.
RecalculateFields(entry.Flags, (int)entry.Sta
rtPos, entry.Unk1);
            }

          
  // Prepare for writing
            this.Bas
eStream.Position = 0;
            this.BaseSt
ream.SetLength(0);
            using var bWri
ter = new BinaryWriter(this.BaseStream, Encod
ing.ASCII, true);

            string fileNam
e = Path.GetFileName(this.originalFileName).T
oLower();

            Random rng = new();
  
          int fileNameCharSum = SumChars(file
Name);
            int randByteCount = fileNa
meCharSum % WzMsConstants.RandByteMod + WzMsC
onstants.RandByteOffset;
            byte[] r
andBytes = new byte[randByteCount];
         
   for (int i = 0; i < randByteCount; i++)
  
          {
                randBytes[i] = (b
yte)rng.Next();
            }

            st
ring saltStr = this.Header.Salt;
            
int saltLen = saltStr.Length;
            byt
e xorVal = randBytes[0];
            byte low
Byte = (byte)(saltLen ^ xorVal);
            
int hashedSaltLen = lowByte;

            byt
e[] saltBytes = new byte[saltLen * 2];
      
      for (int i = 0; i < saltLen; i++)
     
       {
                saltBytes[i * 2] = (
byte)(randBytes[i] ^ (byte)saltStr[i]);
     
           saltBytes[i * 2 + 1] = 0;
        
    }

            int sumSalt = SumUInt16Byt
es(saltBytes);

            byte version = th
is.Header.Version;
            int entryCount
 = this.Entries.Count;
            int hash =
 hashedSaltLen + version + entryCount + sumSa
lt;

            string fileNameWithSalt = th
is.Header.FileNameWithSalt;

            // W
rite unencrypted prefix
            bWriter.W
rite(randBytes);
            bWriter.Write(ha
shedSaltLen);
            bWriter.Write(saltB
ytes);

            long headerStartPos = thi
s.BaseStream.Position;

            // Header
 encryption key
            Span<byte> snowKe
y = stackalloc byte[WzMsConstants.SnowKeyLeng
th];
            DeriveSnowKey(fileNameWithSa
lt, snowKey, false);

            // Write en
crypted header
            using (var snowCip
her = new Snow2CryptoTransform(snowKey, null,
 true))
            {
                using (
var snowEncoderStream = new CryptoStream(this
.BaseStream, snowCipher, CryptoStreamMode.Wri
te, true))
                {
                
    using (var snowWriter = new BinaryWriter(
snowEncoderStream))
                    {
   
                     snowWriter.Write((int)ha
sh);
                        snowWriter.Write
((byte)version);
                        snow
Writer.Write((int)entryCount); // TODO: verif
y if its reading and writing back in the same
 format

                        snowWriter.F
lush();
                        snowEncoderSt
ream.FlushFinalBlock();
                    }

                }
            }

           
 // Padding after header
            int padA
mount = (fileNameCharSum * 3) % WzMsConstants
.HeaderPadMod + WzMsConstants.HeaderPadOffset
;
            byte[] padHeader = new byte[pad
Amount];
            rng.NextBytes(padHeader)
; // randomize the pad header

            bW
riter.Write(padHeader);

            // Entri
es encryption key
            Span<byte> snow
CipherKey2 = stackalloc byte[WzMsConstants.Sn
owKeyLength];
            DeriveSnowKey(fileN
ameWithSalt, snowCipherKey2, true);

        
    // Write encrypted entries
            us
ing (var snowCipher2 = new Snow2CryptoTransfo
rm(snowCipherKey2, null, true))
            {

                using (var snowEncoderStream
2 = new CryptoStream(this.BaseStream, snowCip
her2, CryptoStreamMode.Write, true))
        
        {
                    using (var snow
Writer2 = new BinaryWriter(snowEncoderStream2
, Encoding.Unicode, true))
                  
  {
                        foreach (var entr
y in this.Entries)
                        {

                            int entryNameLen 
= entry.Name.Length;
                        
    snowWriter2.Write(entryNameLen);
        
                    snowWriter2.Write(entry.N
ame.AsSpan());
                            sn
owWriter2.Write(entry.CheckSum);
            
                snowWriter2.Write(entry.Flags
);
                            snowWriter2.Wr
ite((int)entry.StartPos);
                   
         snowWriter2.Write(entry.Size);
     
                       snowWriter2.Write(entr
y.SizeAligned);
                            s
nowWriter2.Write(entry.Unk1);
               
             snowWriter2.Write(entry.Unk2);
 
                           snowWriter2.Write(
entry.EntryKey);
                        }
  
                  }
                }
       
     }

            // Align data start
     
       long dataStartPos = this.BaseStream.Po
sition;
            if ((dataStartPos & 0x3ff
) != 0)
            {
                long pa
d = 0x400 - (dataStartPos & 0x3ff);
         
       byte[] padBytes = new byte[pad];
     
           this.BaseStream.Write(padBytes);
 
               dataStartPos += pad;
         
   }

            // Write encrypted data blo
cks
            long maxPos = dataStartPos;
 
           for (int i = 0; i < this.Entries.C
ount; i++)
            {
                WzMs
Entry entry = this.Entries[i] ?? throw new In
validDataException("MS entry cannot be null."
);
                if (entry.Data == null)
  
                  continue;

                
byte[] encrypted = encryptedDatas[i] ?? throw
 new InvalidDataException("MS entry encryptio
n data is missing.");
                long bl
ockStart = dataStartPos + entry.StartPos * 10
24;
                if (blockStart > this.Bas
eStream.Position)
                    this.Ba
seStream.Position = blockStart;
             
   this.BaseStream.Write(encrypted);

       
         int padSize = entry.SizeAligned - en
try.Size;
                if (padSize > 0)
  
              {
                    byte[] pa
dData = new byte[padSize];
                  
  this.BaseStream.Write(padData);
           
     }

                long blockEnd = block
Start + entry.SizeAligned;
                if
 (blockEnd > maxPos) maxPos = blockEnd;
     
       }

            this.BaseStream.SetLeng
th(maxPos);
            this.BaseStream.Posit
ion = 0;

            // Update header positi
ons
            this.Header.UpdateHeader(hash
, entryCount, headerStartPos, headerStartPos 
+ 9 + padAmount, dataStartPos);

            
return this.BaseStream;
        }
        #en
dregion

        #region Entry Encryption and
 Decryption
        /// <summary>
        ///
 Derives the per-entry image key from salt, n
ame, and entry key.
        /// </summary>
  
      /// <returns>16-byte imgKey.</returns>

        private void DeriveImgKey(WzMsEntry e
ntry, Span<byte> imgKey)
        {
          
  ValidateEntryKeyInputs(entry);
            
uint keyHash = Header.SaltKeyHash;

         
   Span<char> keyHashChars = stackalloc char[
10];
            keyHash.TryFormat(keyHashCha
rs, out int keyHashLength);

            Read
OnlySpan<char> entryNameSpan = entry.Name.AsS
pan();
            ReadOnlySpan<byte> entryKe
ySpan = entry.EntryKey;
            for (int 
i = 0; i < imgKey.Length; i++)
            {

                int digit = keyHashChars[i % 
keyHashLength] - '0';
                int nex
tDigit = keyHashChars[(i + 1) % keyHashLength
] - '0';
                int entryKeyDigit = 
keyHashChars[(i + 2) % keyHashLength] - '0';

                int entryKeyIdx = (entryKeyDi
git + i) % entryKeySpan.Length;
             
   imgKey[i] = (byte)(i + entryNameSpan[i % e
ntryNameSpan.Length] * (
                    
(digit % 2) + entryKeySpan[entryKeyIdx] + ((n
extDigit + i) % 5)
                ));
      
      }
        }

        private void Deriv
eChaCha20ImgKey(WzMsEntry entry, Span<byte> i
mgKey, Span<byte> nonce, out uint counter)
  
      {
            ValidateEntryKeyInputs(en
try);
            uint keyHash = Header.SaltK
eyHash;

            Span<char> keyHashChars 
= stackalloc char[10];
            keyHash.Tr
yFormat(keyHashChars, out int keyHashLength);


            ReadOnlySpan<char> entryNameSpa
n = entry.Name.AsSpan();
            ReadOnly
Span<byte> entryKeySpan = entry.EntryKey;
   
         for (int i = 0; i < imgKey.Length; i
++)
            {
                int digit =
 keyHashChars[i % keyHashLength] - '0';
     
           int nextDigit = keyHashChars[(i + 
1) % keyHashLength] - '0';
                in
t entryKeyDigit = keyHashChars[(i + 2) % keyH
ashLength] - '0';
                int entryKe
yIdx = (entryKeyDigit + i) % entryKeySpan.Len
gth;
                imgKey[i] = (byte)(i + e
ntryNameSpan[i % entryNameSpan.Length] * (
  
                  (digit % 2) + entryKeySpan[
entryKeyIdx] + ((nextDigit + i) % 5)
        
        ));
                imgKey[i] ^= ChaC
ha20KeyObscure[i];
            }

           
 uint keyHash2 = keyHash >> 1;
            ui
nt keyHash3 = keyHash2 ^ 0x6C;
            Sp
an<byte> keyHashData = stackalloc byte[12];
 
           BinaryPrimitives.WriteUInt32Little
Endian(keyHashData[..4], keyHash);
          
  BinaryPrimitives.WriteUInt32LittleEndian(ke
yHashData.Slice(4, 4), keyHash2);
           
 BinaryPrimitives.WriteUInt32LittleEndian(key
HashData.Slice(8, 4), keyHash3);

           
 for (int i = 0, a = 0, b = 0, c = 90, d = 0;
 i < keyHashData.Length; i++)
            {
 
               keyHashData[i] ^= (byte)(d + 1
1 * (i / 11) + (c ^ (i >> 2)) + (a ^ b));
   
             --d;
                a += 8;
   
             b += 17;
                c += 43
;
            }

            nonce.Clear();
 
           keyHashData[..8].CopyTo(nonce[4..]
);
            counter = BinaryPrimitives.Rea
dUInt32LittleEndian(keyHashData[8..]);
      
  }

        private static void ValidateEntr
yKeyInputs(WzMsEntry entry)
        {
       
     if (entry == null)
                throw
 new InvalidDataException("MS entry cannot be
 null.");
            if (string.IsNullOrEmpt
y(entry.Name))
                throw new Inva
lidDataException("MS entry name cannot be emp
ty.");
            if (entry.EntryKey == null
 || entry.EntryKey.Length != WzMsConstants.En
tryKeySize)
                throw new Invalid
DataException("MS entry key has an invalid le
ngth.");
        }

        /// <summary>
   
     /// Decrypts this entry's data from the 
given stream using the provided salt string.

        /// </summary>
        /// <param nam
e="entryData">The entry data of .img.</param>

        /// <returns>Decrypted data as a byt
e array.</returns>
        private Stream Dec
ryptData(WzMsEntry entry)
        {
         
   return new MemoryStream(DecryptDataToArray
(entry), writable: false);
        }

       
 private byte[] DecryptDataToArray(WzMsEntry 
entry)
        {
            ValidateEntryDat
aBounds(entry);
            if (this.Header.V
ersion == WzMsConstants.Version4)
           
     return DecryptDataToArrayVersion4(entry)
;

            Span<byte> imgKey = stackalloc
 byte[WzMsConstants.SnowKeyLength];
         
   DeriveImgKey(entry, imgKey);

            
byte[] buffer = new byte[entry.Size];
       
     if (entry.Data != null)
            {
  
              Buffer.BlockCopy(entry.Data, 0,
 buffer, 0, entry.Size);
            }
      
      else
            {
                this
.BaseStream.Position = entry.StartPos;
      
          this.BaseStream.ReadExactly(buffer)
;
            }

            using (var snowC
ipher = new Snow2CryptoTransform(imgKey, null
, false))
            {
                snowC
ipher.TransformInPlace(buffer);
            }


            int dataLen = Math.Min(buffer.L
ength, WzMsConstants.DoubleEncryptInitialByte
s);
            if (dataLen > 0)
            
{
                using var snowCipher = new 
Snow2CryptoTransform(imgKey, null, false);
  
              snowCipher.TransformInPlace(buf
fer.AsSpan(0, dataLen));
            }

     
       return buffer;
        }

        priv
ate byte[] DecryptDataToArrayVersion4(WzMsEnt
ry entry)
        {
            Span<byte> im
gKey = stackalloc byte[WzMsConstants.ChaCha20
KeyLength];
            Span<byte> nonce = st
ackalloc byte[WzMsConstants.ChaCha20NonceLeng
th];
            DeriveChaCha20ImgKey(entry, 
imgKey, nonce, out uint counter);

          
  byte[] buffer = new byte[entry.Size];
     
       if (entry.Data != null)
            {

                Buffer.BlockCopy(entry.Data, 
0, buffer, 0, entry.Size);
            }
    
        else
            {
                th
is.BaseStream.Position = entry.StartPos;
    
            this.BaseStream.ReadExactly(buffe
r);
            }

            int dataLen = 
Math.Min(buffer.Length, WzMsConstants.DoubleE
ncryptInitialBytes);
            if (dataLen 
> 0)
            {
                using var 
chacha20 = new ChaCha20CryptoTransform(imgKey
, nonce, counter);
                chacha20.T
ransformInPlace(buffer.AsSpan(0, dataLen));
 
           }

            return buffer;
    
    }

        /// <summary>
        /// Encr
ypts the plainData into entry's data
        
/// </summary>
        /// <param name="entry
"></param>
        /// <param name="plainData
"></param>
        /// <returns></returns>
  
      private byte[] EncryptData(WzMsEntry en
try, byte[] plainData)
        {
            
Span<byte> imgKey = stackalloc byte[WzMsConst
ants.SnowKeyLength];
            DeriveImgKey
(entry, imgKey);
            byte[] encrypted
 = plainData.ToArray();

            int data
Len = Math.Min(encrypted.Length, WzMsConstant
s.DoubleEncryptInitialBytes);
            if 
(dataLen > 0)
            {
                u
sing var snowCipher = new Snow2CryptoTransfor
m(imgKey, null, true);
                snowCi
pher.TransformInPlace(encrypted.AsSpan(0, dat
aLen));
            }

            using (var
 snowCipher = new Snow2CryptoTransform(imgKey
, null, true))
            {
                
snowCipher.TransformInPlace(encrypted);
     
       }

            return encrypted;
     
   }
        #endregion

        public void 
Close()
        {
            if (!leaveOpen)

                BaseStream?.Dispose();
     
       BaseStream = null;
        }

        
public void Dispose()
        {
            t
his.Close();
        }
    }
}


