#include "nx/nca_writer.h"
#include <zstd.h>
#include <string.h>

class Keys
{
public:
     Keys()
     {
          u8 kek[0x10] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

          splCryptoGenerateAesKek(headerKekSource, 0, 0, kek);
          splCryptoGenerateAesKey(kek, headerKeySource, headerKey);
          splCryptoGenerateAesKey(kek, headerKeySource + 0x10, headerKey + 0x10);
     }

     u8 headerKekSource[0x10] = { 0x1F, 0x12, 0x91, 0x3A, 0x4A, 0xCB, 0xF0, 0x0D, 0x4C, 0xDE, 0x3A, 0xF6, 0xD5, 0x23, 0x88, 0x2A };
     u8 headerKeySource[0x20] = { 0x5A, 0x3E, 0xD8, 0x4F, 0xDE, 0xC0, 0xD8, 0x26, 0x31, 0xF7, 0xE2, 0x5D, 0x19, 0x7B, 0xF5, 0xD0, 0x1C, 0x9B, 0x7B, 0xFA, 0xF6, 0x28, 0x18, 0x3D, 0x71, 0xF6, 0x4D, 0x73, 0xF1, 0x50, 0xB9, 0xD2 };

     u8 headerKey[0x20] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
};

Keys* g_keys = NULL;

const Keys& keys()
{
     if(!g_keys)
     {
          g_keys = new Keys();
     }
     return *g_keys;
}

template<class T>
T swapEndian(T s)
{
     T result;
     u8* dest = (u8*)&result;
     u8* src = (u8*)&s;
     for (unsigned int i = 0; i < sizeof(s); i++)
     {
          dest[i] = src[sizeof(s) - i - 1];
     }
     return result;
}

void append(std::vector<u8>& buffer, const u8* ptr, u64 sz)
{
     u64 offset = buffer.size();
     buffer.resize(offset + sz);
     memcpy(buffer.data() + offset, ptr, sz);
}

class AesCtr
{
public:
     AesCtr() : m_high(0), m_low(0)
     {
     }

     AesCtr(u64 iv) : m_high(swapEndian(iv)), m_low(0)
     {
     }

     u64& high() { return m_high; }
     u64& low() { return m_low; }
private:
     u64 m_high;
     u64 m_low;
};


class Aes128Ctr
{
public:
     Aes128Ctr(const u8* key, const AesCtr& iv)
     {
          counter = iv;
          aes128CtrContextCreate(&ctx, key, &iv);
          seek(0);
     }

     virtual ~Aes128Ctr()
     {
     }

     void seek(u64 offset)
     {
          counter.low() = swapEndian(offset >> 4);
          aes128CtrContextResetCtr(&ctx, &counter);
     }

     void encrypt(void *dst, const void *src, size_t l)
     {
          aes128CtrCrypt(&ctx, dst, src, l);
     }

     void decrypt(void *dst, const void *src, size_t l)
     {
          encrypt(dst, src, l);
     }
protected:
     AesCtr counter;

     Aes128CtrContext ctx;
};

class AesXtr
{
public:
     AesXtr(const u8* key)
     {
          aes128XtsContextCreate(&ctx, key, key + 0x10, false);
     }

     virtual ~AesXtr()
     {
     }

     void encrypt(void *dst, const void *src, size_t l, size_t sector, size_t sector_size)
     {
          for (size_t i = 0; i < l; i += sector_size)
          {
               aes128XtsContextResetSector(&ctx, sector++, true);
               aes128XtsEncrypt(&ctx, dst, src, sector_size);

               dst = (u8*)dst + sector_size;
               src = (const u8*)src + sector_size;
          }
     }

     void decrypt(void *dst, const void *src, size_t l, size_t sector, size_t sector_size)
     {
          for (size_t i = 0; i < l; i += sector_size)
          {
               aes128XtsContextResetSector(&ctx, sector++, true);
               aes128XtsDecrypt(&ctx, dst, src, sector_size);

               dst = (u8*)dst + sector_size;
               src = (const u8*)src + sector_size;
          }
     }
protected:
     Aes128XtsContext ctx;
};


NcaBodyWriter::NcaBodyWriter(const NcmNcaId& ncaId, u64 offset, std::shared_ptr<nx::ncm::ContentStorage>& contentStorage) : m_contentStorage(contentStorage), m_ncaId(ncaId), m_offset(offset)
{
}

NcaBodyWriter::~NcaBodyWriter()
{
}

u64 NcaBodyWriter::write(const  u8* ptr, u64 sz)
{
     if(isOpen())
     {
          m_contentStorage->WritePlaceholder(m_ncaId, m_offset, (void*)ptr, sz);
          m_offset += sz;
          return sz;
     }

     return 0;
}

bool NcaBodyWriter::isOpen() const
{
     return m_contentStorage != NULL;
}


class NczHeader
{
public:
     static const u64 MAGIC = 0x4E544345535A434E;

     class Section
     {
     public:
          u64 offset;
          u64 size;
          u8 cryptoType;
          u8 padding1[7];
          u64 padding2;
          u8 cryptoKey[0x10];
          u8 cryptoCounter[0x10];
     } PACKED;

     class SectionContext : public Section
     {
     public:
          SectionContext(const Section& s) : Section(s), crypto(s.cryptoKey, AesCtr(swapEndian(((u64*)&s.cryptoCounter)[0])))
          {
          }

          virtual ~SectionContext()
          {
          }

          void decrypt(void* p, u64 sz, u64 offset)
          {
               if (this->cryptoType != 3)
               {
                    return;
               }

               crypto.seek(offset);
               crypto.decrypt(p, p, sz);
          }

          void encrypt(void* p, u64 sz, u64 offset)
          {
               if (this->cryptoType != 3)
               {
                    return;
               }

               crypto.seek(offset);
               crypto.encrypt(p, p, sz);
          }

          Aes128Ctr crypto;
     };

     const bool isValid()
     {
          return m_magic == MAGIC && m_sectionCount < 0xFFFF;
     }

     const u64 size() const
     {
          return sizeof(m_magic) + sizeof(m_sectionCount) + sizeof(Section) * m_sectionCount;
     }

     const Section& section(u64 i) const
     {
          return m_sections[i];
     }

     const u64 sectionCount() const
     {
          return m_sectionCount;
     }

protected:
     u64 m_magic;
     u64 m_sectionCount;
     Section m_sections[1];
} PACKED;

class NczBodyWriter : public NcaBodyWriter
{
public:
     NczBodyWriter(const NcmNcaId& ncaId, u64 offset, std::shared_ptr<nx::ncm::ContentStorage>& contentStorage) : NcaBodyWriter(ncaId, offset, contentStorage)
     {
          buffIn = malloc(buffInSize);
          buffOut = malloc(buffOutSize);

          dctx = ZSTD_createDCtx();
     }

     virtual ~NczBodyWriter()
     {
          close();

          for (auto& i : sections)
          {
               if (i)
               {
                    delete i;
                    i = NULL;
               }
          }

          if (dctx)
          {
               ZSTD_freeDCtx(dctx);
               dctx = NULL;
          }
     }

     bool close()
     {
          if (this->m_buffer.size())
          {
               processChunk(m_buffer.data(), m_buffer.size());
          }

          flush();

          return true;
     }

     bool flush()
     {
          if(!isOpen())
          {
               return false;
          }

          if (m_deflateBuffer.size())
          {
               m_contentStorage->WritePlaceholder(m_ncaId, m_offset, m_deflateBuffer.data(), m_deflateBuffer.size());
               m_offset += m_deflateBuffer.size();
               m_deflateBuffer.resize(0);
          }
          return true;
     }

     NczHeader::SectionContext& section(u64 offset)
     {
          for (u64 i = 0; i < sections.size(); i++)
          {
               if (offset >= sections[i]->offset && offset < sections[i]->offset + sections[i]->size)
               {
                    return *sections[i];
               }
          }
          return *sections[0];
     }

     bool encrypt(const void* ptr, u64 sz, u64 offset)
     {
          const u8* start = (u8*)ptr;
          const u8* end = start + sz;

          while (start < end)
          {
               auto& s = section(offset);

               u64 sectionEnd = s.offset + s.size;

               u64 chunk = offset + sz > sectionEnd ? sectionEnd - offset : sz;

               s.encrypt((void*)start, chunk, offset);

               offset += chunk;
               start += chunk;
               sz -= chunk;
          }

          return true;
     }

     u64 processChunk(const  u8* ptr, u64 sz)
     {
          ZSTD_inBuffer input = { ptr, sz, 0 };
          m_deflateBuffer.resize(sz);
          m_deflateBuffer.resize(0);

          while (input.pos < input.size)
          {
               ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
               size_t const ret = ZSTD_decompressStream(dctx, &output, &input);

               if (ZSTD_isError(ret))
               {
                    printf("%s\n", ZSTD_getErrorName(ret));
                    return false;
               }

               append(m_deflateBuffer, (const u8*)buffOut, output.pos);

               if (m_deflateBuffer.size() >= 0x1000000) // 16 MB
               {
                    encrypt(m_deflateBuffer.data(), m_deflateBuffer.size(), m_offset);

                    flush();
               }

          }

          if (m_deflateBuffer.size())
          {
               encrypt(m_deflateBuffer.data(), m_deflateBuffer.size(), m_offset);

               flush();
          }
          return 1;
     }

     u64 write(const  u8* ptr, u64 sz) override
     {
          if (!m_sectionsInitialized)
          {
               if (!m_buffer.size())
               {
                    append(m_buffer, ptr, sizeof(u64)*2);
                    ptr += sizeof(u64) * 2;
                    sz -= sizeof(u64) * 2;
               }

               auto header = (NczHeader*)m_buffer.data();

               if (m_buffer.size() + sz > header->size())
               {
                    u64 remainder = header->size() - m_buffer.size();
                    append(m_buffer, ptr, remainder);
                    ptr += remainder;
                    sz -= remainder;
               }
               else
               {
                    append(m_buffer, ptr, sz);
                    ptr += sz;
                    sz = 0;
               }

               header = (NczHeader*)m_buffer.data();

               if (m_buffer.size() == header->size())
               {
                    for (u64 i = 0; i < header->sectionCount(); i++)
                    {
                         sections.push_back(new NczHeader::SectionContext(header->section(i)));
                    }

                    m_sectionsInitialized = true;
                    m_buffer.resize(0);
               }
          }

          while (sz)
          {
               if (m_buffer.size() + sz >= 0x1000000)
               {
                    u64 chunk = 0x1000000 - m_buffer.size();
                    append(m_buffer, ptr, chunk);

                    processChunk(m_buffer.data(), m_buffer.size());
                    m_buffer.resize(0);

                    sz -= chunk;
                    ptr += chunk;
               }
               else
               {
                    append(m_buffer, ptr, sz);
                    sz = 0;
               }

          }

          return sz;
     }

     size_t const buffInSize = ZSTD_DStreamInSize();
     size_t const buffOutSize = ZSTD_DStreamOutSize();

     void* buffIn = NULL;
     void* buffOut = NULL;

     ZSTD_DCtx* dctx = NULL;

     std::vector<u8> m_buffer;
     std::vector<u8> m_deflateBuffer;

     bool m_sectionsInitialized = false;

     std::vector<NczHeader::SectionContext*> sections;
};

NcaWriter::NcaWriter(const NcmNcaId& ncaId, std::shared_ptr<nx::ncm::ContentStorage>& contentStorage) : m_ncaId(ncaId), m_contentStorage(contentStorage), m_writer(NULL)
{
}

NcaWriter::~NcaWriter()
{
     close();
}

bool NcaWriter::close()
{
     if (m_writer)
     {
          m_writer = NULL;
     }
     else if(m_buffer.size())
     {
          if(isOpen())
          {
               m_contentStorage->CreatePlaceholder(m_ncaId, m_ncaId, m_buffer.size());
               m_contentStorage->WritePlaceholder(m_ncaId, 0, m_buffer.data(), m_buffer.size());
          }

          m_buffer.resize(0);
     }
     m_contentStorage = NULL;
     return true;
}

bool NcaWriter::isOpen() const
{
     return (bool)m_contentStorage;
}

u64 NcaWriter::write(const  u8* ptr, u64 sz)
{
     if (m_buffer.size() < NCA_HEADER_SIZE)
     {
          if (m_buffer.size() + sz > NCA_HEADER_SIZE)
          {
               u64 remainder = NCA_HEADER_SIZE - m_buffer.size();
               append(m_buffer, ptr, remainder);

               ptr += remainder;
               sz -= remainder;
          }
          else
          {
               append(m_buffer, ptr, sz);
               ptr += sz;
               sz = 0;
          }

          if (m_buffer.size() == NCA_HEADER_SIZE)
          {
               NcaHeader header;
               memcpy(&header, m_buffer.data(), sizeof(header));
               AesXtr crypto(keys().headerKey);
               crypto.decrypt(&header, &header, sizeof(header), 0, 0x200);

               if (header.magic == MAGIC_NCA3)
               {
                    if(isOpen())
                    {
                         m_contentStorage->CreatePlaceholder(m_ncaId, m_ncaId, header.nca_size);
                    }
               }
               else
               {
                    throw "Invalid NCA magic";
               }

               if(isOpen())
               {
                    m_contentStorage->WritePlaceholder(m_ncaId, 0, m_buffer.data(), m_buffer.size());
               }
          }
     }

     if (sz)
     {
          if (!m_writer)
          {
               if (sz >= sizeof(NczHeader::MAGIC))
               {
                    if (*(u64*)ptr == NczHeader::MAGIC)
                    {
                         m_writer = std::shared_ptr<NcaBodyWriter>(new NczBodyWriter(m_ncaId, m_buffer.size(), m_contentStorage));
                    }
                    else
                    {
                         m_writer = std::shared_ptr<NcaBodyWriter>(new NcaBodyWriter(m_ncaId, m_buffer.size(), m_contentStorage));
                    }
               }
               else
               {
                    throw "not enough data to read ncz header";
               }
          }

          if(m_writer)
          {
               m_writer->write(ptr, sz);
          }
          else
          {
               throw "null writer";
          }
     }

     return sz;
}

