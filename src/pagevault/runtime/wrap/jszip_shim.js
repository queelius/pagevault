  // Minimal ZIP reader using native browser APIs (no JSZip dependency).
  //
  // Uses the browser's built-in DecompressionStream API (modern browsers)
  // to decompress deflate-compressed zip entries.
  //
  // Exposes: window.__pagevault_ZipReader

  (function() {
    'use strict';

    class ZipReader {
      constructor(buffer) {
        this.buffer = buffer;
        this.view = new DataView(buffer);
        this.entries = [];
        this._parse();
      }

      _parse() {
        // Find end of central directory
        let eocdOffset = -1;
        for (let i = this.buffer.byteLength - 22; i >= 0; i--) {
          if (this.view.getUint32(i, true) === 0x06054b50) {
            eocdOffset = i;
            break;
          }
        }
        if (eocdOffset === -1) throw new Error('Invalid ZIP file');

        const cdOffset = this.view.getUint32(eocdOffset + 16, true);
        const cdCount = this.view.getUint16(eocdOffset + 10, true);

        let offset = cdOffset;
        for (let i = 0; i < cdCount; i++) {
          if (this.view.getUint32(offset, true) !== 0x02014b50) break;

          const compression = this.view.getUint16(offset + 10, true);
          const compSize = this.view.getUint32(offset + 20, true);
          const uncompSize = this.view.getUint32(offset + 24, true);
          const nameLen = this.view.getUint16(offset + 28, true);
          const extraLen = this.view.getUint16(offset + 30, true);
          const commentLen = this.view.getUint16(offset + 32, true);
          const localHeaderOffset = this.view.getUint32(offset + 42, true);

          const nameBytes = new Uint8Array(this.buffer, offset + 46, nameLen);
          const name = new TextDecoder().decode(nameBytes);

          this.entries.push({
            name, compression, compSize, uncompSize, localHeaderOffset
          });

          offset += 46 + nameLen + extraLen + commentLen;
        }
      }

      async getFile(name) {
        const entry = this.entries.find(e => e.name === name);
        if (!entry) return null;

        // Read local file header to find data offset
        const lh = entry.localHeaderOffset;
        const lhNameLen = this.view.getUint16(lh + 26, true);
        const lhExtraLen = this.view.getUint16(lh + 28, true);
        const dataOffset = lh + 30 + lhNameLen + lhExtraLen;

        const compressedData = new Uint8Array(this.buffer, dataOffset, entry.compSize);

        if (entry.compression === 0) {
          // Stored (no compression)
          return compressedData;
        } else if (entry.compression === 8) {
          // Deflate
          const ds = new DecompressionStream('deflate-raw');
          const writer = ds.writable.getWriter();
          const reader = ds.readable.getReader();

          writer.write(compressedData);
          writer.close();

          const chunks = [];
          let totalLen = 0;
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            totalLen += value.length;
          }

          const result = new Uint8Array(totalLen);
          let off = 0;
          for (const chunk of chunks) {
            result.set(chunk, off);
            off += chunk.length;
          }
          return result;
        }

        throw new Error('Unsupported compression: ' + entry.compression);
      }

      getFileNames() {
        return this.entries.map(e => e.name).filter(n => !n.endsWith('/'));
      }
    }

    window.__pagevault_ZipReader = ZipReader;
  })();
