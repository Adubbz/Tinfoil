#include "install/http_nsp.hpp"

#include <switch.h>
#include <threads.h>
#include "data/buffered_placeholder_writer.hpp"
#include "util/title_util.hpp"
#include "error.hpp"
#include "debug.h"

namespace tin::install::nsp
{
    HTTPNSP::HTTPNSP(std::string url) :
        m_download(url)
    {

    }

    struct StreamFuncArgs
    {
        tin::network::HTTPDownload* download;
        tin::data::BufferedPlaceholderWriter* bufferedPlaceholderWriter;
        u64 pfs0Offset;
        u64 ncaSize;
    };

    int CurlStreamFunc(void* in)
    {
        StreamFuncArgs* args = reinterpret_cast<StreamFuncArgs*>(in);

        auto streamFunc = [&](u8* streamBuf, size_t streamBufSize) -> size_t
        {
            while (true)
            {
                if (args->bufferedPlaceholderWriter->CanAppendData(streamBufSize))
                    break;
            }

            args->bufferedPlaceholderWriter->AppendData(streamBuf, streamBufSize);
            return streamBufSize;
        };

        args->download->StreamDataRange(args->pfs0Offset, args->ncaSize, streamFunc);
        return 0;
    }

    int PlaceholderWriteFunc(void* in)
    {
        StreamFuncArgs* args = reinterpret_cast<StreamFuncArgs*>(in);

        while (!args->bufferedPlaceholderWriter->IsPlaceholderComplete())
        {
            if (args->bufferedPlaceholderWriter->CanWriteSegmentToPlaceholder())
                args->bufferedPlaceholderWriter->WriteSegmentToPlaceholder();
        }

        return 0;
    }

    void HTTPNSP::StreamToPlaceholder(nx::ncm::ContentStorage& contentStorage, NcmNcaId placeholderId)
    {
        const PFS0FileEntry* fileEntry = this->GetFileEntryByNcaId(placeholderId);
        std::string ncaFileName = this->GetFileEntryName(fileEntry);

        LOG_DEBUG("Retrieving %s\n", ncaFileName.c_str());
        size_t ncaSize = fileEntry->fileSize;

        tin::data::BufferedPlaceholderWriter bufferedPlaceholderWriter(&contentStorage, placeholderId, ncaSize);
        StreamFuncArgs args;
        args.download = &m_download;
        args.bufferedPlaceholderWriter = &bufferedPlaceholderWriter;
        args.pfs0Offset = this->GetDataOffset() + fileEntry->dataOffset;
        args.ncaSize = ncaSize;
        thrd_t curlThread;
        thrd_t writeThread;

        thrd_create(&curlThread, CurlStreamFunc, &args);
        thrd_create(&writeThread, PlaceholderWriteFunc, &args);
        
        u64 freq = armGetSystemTickFreq();
        u64 startTime = armGetSystemTick();
        size_t startSizeBuffered = 0;
        double speed = 0.0;

        consoleUpdate(NULL);

        while (!bufferedPlaceholderWriter.IsBufferDataComplete())
        {
            u64 newTime = armGetSystemTick();

            if (newTime - startTime >= freq)
            {
                size_t newSizeBuffered = bufferedPlaceholderWriter.GetSizeBuffered();
                double mbBuffered = (newSizeBuffered / 1000000.0) - (startSizeBuffered / 1000000.0);
                double duration = ((double)(newTime - startTime) / (double)freq);
                speed =  mbBuffered / duration;

                startTime = newTime;
                startSizeBuffered = newSizeBuffered;
            }

            u64 totalSizeMB = bufferedPlaceholderWriter.GetTotalDataSize() / 1000000;
            u64 downloadSizeMB = bufferedPlaceholderWriter.GetSizeBuffered() / 1000000;
            int downloadProgress = (int)(((double)bufferedPlaceholderWriter.GetSizeBuffered() / (double)bufferedPlaceholderWriter.GetTotalDataSize()) * 100.0);

            printf("> Download Progress: %lu/%lu MB (%i%s) (%.2f MB/s)\r", downloadSizeMB, totalSizeMB, downloadProgress, "%", speed);
            consoleUpdate(NULL);
        }

        u64 totalSizeMB = bufferedPlaceholderWriter.GetTotalDataSize() / 1000000;

        while (!bufferedPlaceholderWriter.IsPlaceholderComplete())
        {
            u64 installSizeMB = bufferedPlaceholderWriter.GetSizeWrittenToPlaceholder() / 1000000;
            int installProgress = (int)(((double)bufferedPlaceholderWriter.GetSizeWrittenToPlaceholder() / (double)bufferedPlaceholderWriter.GetTotalDataSize()) * 100.0);

            printf("> Install Progress: %lu/%lu MB (%i%s)\r", installSizeMB, totalSizeMB, installProgress, "%");
            consoleUpdate(NULL);
        }

        thrd_join(curlThread, NULL);
        thrd_join(writeThread, NULL);
        consoleUpdate(NULL);
    }

    void HTTPNSP::BufferData(void* buf, off_t offset, size_t size)
    {
        m_download.BufferDataRange(buf, offset, size, nullptr);
    }
}