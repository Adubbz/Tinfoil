#pragma once

#include <atomic>
#include <switch/types.h>
#include <memory>

#include "nx/ncm.hpp"

namespace tin::data
{
    static const size_t BUFFER_SEGMENT_DATA_SIZE = 0x800000; // Approximately 8MB

    struct BufferSegment
    {
        std::atomic_bool isFinalized = false;
        u64 writeOffset = 0;
        u8 data[BUFFER_SEGMENT_DATA_SIZE] = {0};
    };

    // Receives data in a circular buffer split into 8MB segments
    class BufferedPlaceholderWriter
    {
        private:
            size_t m_totalDataSize = 0;
            size_t m_sizeBuffered = 0;
            size_t m_sizeWrittenToPlaceholder = 0;

            // The current segment to which further data will be appended
            u64 m_currentFreeSegment = 0;
            BufferSegment* m_currentFreeSegmentPtr = NULL;
            // The current segment that will be written to the placeholder
            u64 m_currentSegmentToWrite = 0;
            BufferSegment* m_currentSegmentToWritePtr = NULL;

            std::unique_ptr<BufferSegment[]> m_bufferSegments;

            nx::ncm::ContentStorage* m_contentStorage;
            NcmContentId m_ncaId;

        public:
            static const int NUM_BUFFER_SEGMENTS = 4;

            BufferedPlaceholderWriter(nx::ncm::ContentStorage* contentStorage, NcmContentId ncaId, size_t totalDataSize);

            void AppendData(void* source, size_t length);
            bool CanAppendData(size_t length);

            void WriteSegmentToPlaceholder();
            bool CanWriteSegmentToPlaceholder();

            // Determine the number of segments required to fit data of this size
            u32 CalcNumSegmentsRequired(size_t size);

            // Check if there are enough free segments to fit data of this size
            bool IsSizeAvailable(size_t size);

            bool IsBufferDataComplete();
            bool IsPlaceholderComplete();

            size_t GetTotalDataSize();
            size_t GetSizeBuffered();
            size_t GetSizeWrittenToPlaceholder();

            void DebugPrintBuffers();
    };
}