using System.Buffers;
using System.Buffers.Text;
using System.IO.Pipelines;
using System.Text;
using RapidYencSharp;
using UsenetSharp.Encryption;
using UsenetSharp.Exceptions;
using UsenetSharp.Models;
using UsenetSharp.Streams;

namespace UsenetSharp.Clients;

internal sealed class NntpYencBodyDecoder(
    NntpLineReader reader,
    PipeWriter writer,
    TaskCompletionSource<UsenetYencHeader?> headersCompletion,
    DecodedBodyReadStream decodedStream,
    UsenetClientOptions options,
    int flushThreshold,
    YencEncryptionContext? encryptionContext = null)
{
    private enum BodyPhase
    {
        SeekingYBegin,
        AwaitingYPartOrData,
        DecodingData,
        AfterYEnd
    }

    public async Task ReadAsync(
        CoalescedReadTimeout readTimeout,
        CancellationToken cancellationToken = default)
    {
        // Encrypted articles are restored and authenticated before any byte is
        // released: buffer this one segment, open it, then serve plaintext.
        if (encryptionContext is not null)
        {
            await ReadEncryptedAsync(readTimeout, cancellationToken).ConfigureAwait(false);
            return;
        }

        await ReadPlainAsync(readTimeout, cancellationToken).ConfigureAwait(false);
    }

    private async Task ReadEncryptedAsync(
        CoalescedReadTimeout readTimeout,
        CancellationToken cancellationToken)
    {
        var rawLines = new List<byte[]>();
        long accumulatedBytes = 0;
        var pendingObservedBytes = 0;
        try
        {
            while (true)
            {
                NntpReadBuffer? batch;
                try
                {
                    batch = await ReadCompleteLinesAsync(readTimeout).ConfigureAwait(false);
                }
                catch (IOException)
                {
                    throw new UsenetProtocolException(
                        "The NNTP connection closed before the article body terminator was received.");
                }

                if (!batch.HasValue)
                {
                    throw new UsenetProtocolException(
                        "The NNTP connection closed before the article body terminator was received.");
                }

                var span = batch.Value.Memory.Span;
                var offset = 0;
                var consume = 0;
                var hitTerminator = false;
                try
                {
                    while (TryReadLine(
                        span,
                        ref offset,
                        out var rawStart,
                        out var rawLength,
                        out var contentStart,
                        out var contentLength))
                    {
                        var rawLine = span.Slice(rawStart, rawLength);
                        var content = span.Slice(contentStart, contentLength);
                        consume = rawStart + rawLength;
                        if (contentLength == 1 && content[0] == (byte)'.')
                        {
                            hitTerminator = true;
                            break;
                        }

                        PayloadBytesObserver.Accumulate(
                            options.PayloadBytesObserver,
                            ref pendingObservedBytes,
                            contentLength + 2);
                        // Dot-unstuffing mirrors the raw BODY path (leading
                        // ".." loses its first dot); headers/data keep CRLF.
                        var stored = contentLength >= 1 && content[0] == (byte)'.'
                            && rawLine.Length >= 2 && rawLine[0] == (byte)'.' && rawLine[1] == (byte)'.'
                            ? rawLine[1..].ToArray()
                            : rawLine.ToArray();
                        // F5: one segment may be buffered for authentication,
                        // never an unbounded "article" — reuse the plain path's
                        // drain ceiling (options.AbandonedBodyDrainLimit). An
                        // oversized copy is provider corruption: fail over with
                        // zero bytes released (nothing has been written yet).
                        accumulatedBytes += stored.Length;
                        if (accumulatedBytes > options.AbandonedBodyDrainLimit)
                        {
                            throw new YencEncryptionFailoverException(
                                "Encrypted article exceeds the configured one-segment accumulation limit.");
                        }

                        rawLines.Add(stored);
                    }
                }
                finally
                {
                    if (consume > 0)
                    {
                        reader.Advance(consume);
                    }
                }

                if (hitTerminator)
                {
                    break;
                }

                cancellationToken.ThrowIfCancellationRequested();
            }
        }
        finally
        {
            PayloadBytesObserver.Flush(options.PayloadBytesObserver, ref pendingObservedBytes);
        }

        var article = ConcatLines(rawLines);
        // Restore + grammar + dual-salt/index validation run before the KDF
        // where the grammar alone suffices, and before any byte is written.
        var restored = YencControlRestorer.Restore(encryptionContext!, article);
        var stripped = YencControlRestorer.RemoveYencryptionLine(restored.RestoredBlock);
        var lines = YencControlRestorer.SplitLinesPreservingEndings(stripped);
        while (lines.Count > 0 && YencControlRestorer.SplitEnding(lines[^1]).Content.Length == 0)
            lines.RemoveAt(lines.Count - 1);
        if (lines.Count < 2)
            throw new YencEncryptionFailoverException("Encrypted article has no =yend trailer.");

        var ybeginContent = YencControlRestorer.SplitEnding(lines[0]).Content;
        var isMultipart = restored.Geometry.IsMultipart;
        var ypartContent = isMultipart
            ? YencControlRestorer.SplitEnding(lines[1]).Content
            : Array.Empty<byte>();
        var headers = EncryptedYencAssembler.ParseRestoredHeaders(
            ybeginContent, ypartContent, restored);

        var footerContent = YencControlRestorer.SplitEnding(lines[^1]).Content;
        if (!YencStream.StartsWithYEnd(footerContent))
            throw new YencEncryptionFailoverException("Encrypted article has no =yend trailer.");

        // Ordinary yEnc data decode (ciphertext) + wire CRC over ciphertext.
        var ciphertext = DecodeEncryptedDataLines(lines, isMultipart ? 2 : 1);
        EncryptedYencAssembler.CheckCiphertextCrc(footerContent, isMultipart, ciphertext);

        var opened = EncryptedYencAssembler.Open(
            encryptionContext!,
            new EncryptedYencAssembler.DecodedCiphertext(ciphertext, restored, headers));
        var plaintext = opened.Plaintext;

        // F1: headers are published ONLY after the AEAD open succeeds.
        // Publishing the restored (unauthenticated) geometry earlier would let
        // GetYencHeadersAsync — and HeaderCachingNntpClient above it — cache
        // header geometry from a tampered/ciphertext-corrupt article that
        // merely has a valid password. The plain path below is untouched.
        headersCompletion.TrySetResult(opened.Headers);

        if (options.PayloadBandwidthAcquirer is { } acquire)
        {
            await acquire(plaintext.Length, cancellationToken).ConfigureAwait(false);
        }

        var destination = writer.GetSpan(plaintext.Length);
        plaintext.CopyTo(destination);
        decodedStream.AddBufferedBytes(plaintext.Length);
        writer.Advance(plaintext.Length);
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static byte[] ConcatLines(List<byte[]> lines)
    {
        var total = 0;
        foreach (var line in lines)
            total += line.Length;
        var result = new byte[total];
        var offset = 0;
        foreach (var line in lines)
        {
            line.CopyTo(result, offset);
            offset += line.Length;
        }

        return result;
    }

    private static byte[] DecodeEncryptedDataLines(List<byte[]> lines, int dataStart)
    {
        using var output = new MemoryStream();
        RapidYencDecoderState? state = RapidYencDecoderState.RYDEC_STATE_CRLF;
        for (var i = dataStart; i < lines.Count - 1; i++)
        {
            var raw = lines[i];
            if (raw.Length == 0)
                continue;
            var chunk = new byte[raw.Length];
            var written = YencDecoder.DecodeEx(raw, chunk, ref state, isRaw: true);
            output.Write(chunk, 0, written);
        }

        return output.ToArray();
    }

    private async Task ReadPlainAsync(
        CoalescedReadTimeout readTimeout,
        CancellationToken cancellationToken = default)
    {
        byte[]? ybeginBuffer = null;
        byte[]? yendBuffer = null;
        var pendingObservedBytes = 0;
        try
        {
            var unflushedDecodedBytes = 0;
            var shouldWrite = true;
            var phase = BodyPhase.SeekingYBegin;
            var isMultipart = false;
            long drainedBytes = 0;
            var pendingDrainCharge = 0;
            long skippedBytes = 0;
            var ybeginLength = 0;
            var yendLength = 0;
            RapidYencDecoderState? decoderState = RapidYencDecoderState.RYDEC_STATE_CRLF;
            uint decodedCrc32 = 0;

            void DecodePayload(ReadOnlySpan<byte> rawPayload)
            {
                if (!shouldWrite || rawPayload.IsEmpty)
                {
                    return;
                }

                var destination = writer.GetSpan(rawPayload.Length);
                var decodedLength = YencDecoder.DecodeEx(
                    rawPayload, destination, ref decoderState, isRaw: true);
                if (options.CrcValidation != YencCrcValidationMode.Off)
                {
                    decodedCrc32 = Crc32.Compute(destination[..decodedLength], decodedCrc32);
                }

                decodedStream.AddBufferedBytes(decodedLength);
                writer.Advance(decodedLength);
                unflushedDecodedBytes += decodedLength;
            }

            async ValueTask FlushDecodedAsync()
            {
                if (!shouldWrite || unflushedDecodedBytes == 0)
                {
                    return;
                }

                if (options.PayloadBandwidthAcquirer is { } acquire)
                {
                    await acquire(unflushedDecodedBytes, cancellationToken).ConfigureAwait(false);
                }

                var result = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                unflushedDecodedBytes = 0;
                shouldWrite = !result.IsCompleted && !result.IsCanceled;
            }

            async ValueTask ChargePendingDrainAsync()
            {
                if (pendingDrainCharge <= 0 || options.PayloadBandwidthAcquirer is not { } acquire)
                {
                    pendingDrainCharge = 0;
                    return;
                }

                var remaining = pendingDrainCharge;
                pendingDrainCharge = 0;
                const int chunk = 64 * 1024;
                while (remaining > 0)
                {
                    var n = Math.Min(remaining, chunk);
                    await acquire(n, cancellationToken).ConfigureAwait(false);
                    remaining -= n;
                }
            }

            while (true)
            {
                NntpReadBuffer? batch;
                try
                {
                    batch = await ReadCompleteLinesAsync(readTimeout).ConfigureAwait(false);
                }
                catch (IOException)
                {
                    throw new UsenetProtocolException(
                        "The NNTP connection closed before the article body terminator was received.");
                }

                if (!batch.HasValue)
                {
                    throw new UsenetProtocolException(
                        "The NNTP connection closed before the article body terminator was received.");
                }

                var span = batch.Value.Memory.Span;
                var offset = 0;
                var payloadStart = -1;
                var consume = 0;
                var hitTerminator = false;
                var hitYEnd = false;

                try
                {
                    while (TryReadLine(
                        span,
                        ref offset,
                        out var rawStart,
                        out var rawLength,
                        out var contentStart,
                        out var contentLength))
                    {
                        var content = span.Slice(contentStart, contentLength);
                        if (contentLength == 1 && content[0] == (byte)'.')
                        {
                            if (payloadStart >= 0)
                            {
                                DecodePayload(span[payloadStart..rawStart]);
                            }

                            payloadStart = -1;
                            consume = rawStart + rawLength;
                            if (phase == BodyPhase.SeekingYBegin)
                            {
                                throw new InvalidDataException(
                                    "Reached end of NNTP body without finding =ybegin header.");
                            }

                            if (phase == BodyPhase.AwaitingYPartOrData)
                            {
                                headersCompletion.TrySetResult(
                                    YencStream.ParseYencHeaders(
                                        ybeginBuffer.AsSpan(0, ybeginLength)));
                                phase = BodyPhase.DecodingData;
                            }

                            hitTerminator = true;
                            break;
                        }

                        PayloadBytesObserver.Accumulate(
                            options.PayloadBytesObserver,
                            ref pendingObservedBytes,
                            contentLength + 2);

                        if (!shouldWrite)
                        {
                            payloadStart = -1;
                            drainedBytes += contentLength + 2;
                            pendingDrainCharge += contentLength + 2;
                            if (drainedBytes > options.AbandonedBodyDrainLimit)
                            {
                                consume = rawStart + rawLength;
                                throw new UsenetBodyAbandonedException();
                            }

                            consume = rawStart + rawLength;
                            continue;
                        }

                        if (phase == BodyPhase.AfterYEnd)
                        {
                            skippedBytes += contentLength + 2;
                            if (skippedBytes > options.AbandonedBodyDrainLimit)
                            {
                                consume = rawStart + rawLength;
                                throw new UsenetProtocolException(
                                    "The NNTP body contained more non-yEnc data than the configured drain limit.");
                            }

                            consume = rawStart + rawLength;
                            continue;
                        }

                        if (phase == BodyPhase.SeekingYBegin)
                        {
                            if (YencStream.StartsWithYBegin(content))
                            {
                                ybeginBuffer = ArrayPool<byte>.Shared.Rent(contentLength);
                                content.CopyTo(ybeginBuffer);
                                ybeginLength = contentLength;
                                phase = BodyPhase.AwaitingYPartOrData;
                            }
                            else
                            {
                                skippedBytes += contentLength + 2;
                                if (skippedBytes > options.AbandonedBodyDrainLimit)
                                {
                                    consume = rawStart + rawLength;
                                    throw new UsenetProtocolException(
                                        "The NNTP body contained more non-yEnc data than the configured drain limit.");
                                }
                            }

                            consume = rawStart + rawLength;
                            continue;
                        }

                        if (phase == BodyPhase.AwaitingYPartOrData)
                        {
                            if (YencStream.StartsWithYPart(content))
                            {
                                consume = rawStart + rawLength;
                                headersCompletion.TrySetResult(
                                    YencStream.ParseYencHeaders(
                                        ybeginBuffer.AsSpan(0, ybeginLength), content));
                                isMultipart = true;
                                phase = BodyPhase.DecodingData;
                                continue;
                            }

                            consume = rawStart + rawLength;
                            headersCompletion.TrySetResult(
                                YencStream.ParseYencHeaders(
                                    ybeginBuffer.AsSpan(0, ybeginLength)));
                            phase = BodyPhase.DecodingData;
                        }

                        if (YencStream.StartsWithYEnd(content))
                        {
                            if (payloadStart >= 0)
                            {
                                DecodePayload(span[payloadStart..rawStart]);
                            }

                            payloadStart = -1;
                            if (yendBuffer != null)
                            {
                                ArrayPool<byte>.Shared.Return(yendBuffer);
                            }

                            yendBuffer = ArrayPool<byte>.Shared.Rent(contentLength);
                            content.CopyTo(yendBuffer);
                            yendLength = contentLength;
                            phase = BodyPhase.AfterYEnd;
                            consume = rawStart + rawLength;
                            hitYEnd = true;
                            break;
                        }

                        if (payloadStart < 0)
                        {
                            payloadStart = rawStart;
                        }

                        consume = rawStart + rawLength;
                    }

                    if (payloadStart >= 0)
                    {
                        DecodePayload(span[payloadStart..consume]);
                    }
                }
                catch
                {
                    if (consume > 0)
                    {
                        reader.Advance(consume);
                    }

                    throw;
                }

                if (consume > 0)
                {
                    reader.Advance(consume);
                }

                if (hitYEnd)
                {
                    await FlushDecodedAsync().ConfigureAwait(false);
                    if (options.CrcValidation != YencCrcValidationMode.Off && shouldWrite)
                    {
                        ValidateDecodedBodyCrc32(
                            yendBuffer.AsSpan(0, yendLength),
                            isMultipart,
                            decodedCrc32,
                            options.CrcValidation);
                    }

                    continue;
                }

                if (unflushedDecodedBytes >= flushThreshold)
                {
                    await FlushDecodedAsync().ConfigureAwait(false);
                }

                if (hitTerminator)
                {
                    await FlushDecodedAsync().ConfigureAwait(false);
                    if (options.CrcValidation == YencCrcValidationMode.Require &&
                        phase != BodyPhase.AfterYEnd)
                    {
                        throw new InvalidDataException(
                            "Reached end of NNTP body without finding a yEnc trailer.");
                    }

                    break;
                }

                if (pendingDrainCharge >= 64 * 1024)
                {
                    await ChargePendingDrainAsync().ConfigureAwait(false);
                }
            }

            await ChargePendingDrainAsync().ConfigureAwait(false);
        }
        finally
        {
            PayloadBytesObserver.Flush(options.PayloadBytesObserver, ref pendingObservedBytes);

            if (ybeginBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(ybeginBuffer);
            }

            if (yendBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(yendBuffer);
            }
        }
    }

    private async ValueTask<NntpReadBuffer?> ReadCompleteLinesAsync(
        CoalescedReadTimeout readTimeout)
    {
        readTimeout.BeginIo();
        try
        {
            return await reader.ReadCompleteLinesAsync(readTimeout.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (readTimeout.IsTimeoutCancellation)
        {
            throw new TimeoutException("Timeout reading from NNTP stream.");
        }
        finally
        {
            readTimeout.EndIo();
        }
    }

    private static bool TryReadLine(
        ReadOnlySpan<byte> batch,
        ref int offset,
        out int rawStart,
        out int rawLength,
        out int contentStart,
        out int contentLength)
    {
        if (offset >= batch.Length)
        {
            rawStart = 0;
            rawLength = 0;
            contentStart = 0;
            contentLength = 0;
            return false;
        }

        var relativeNewline = batch[offset..].IndexOf((byte)'\n');
        if (relativeNewline < 0)
        {
            throw new InvalidOperationException("NNTP batch ended without a line terminator.");
        }

        rawStart = offset;
        rawLength = relativeNewline + 1;
        contentStart = rawStart;
        contentLength = relativeNewline;
        if (contentLength > 0 && batch[contentStart + contentLength - 1] == (byte)'\r')
        {
            contentLength--;
        }

        offset += rawLength;
        return true;
    }

    private static void ValidateDecodedBodyCrc32(
        ReadOnlySpan<byte> yendLine,
        bool isMultipart,
        uint actualCrc32,
        YencCrcValidationMode mode)
    {
        var fieldName = isMultipart ? "pcrc32"u8 : "crc32"u8;
        if (!TryParseYencTrailerCrc32(yendLine, fieldName, out var expectedCrc32))
        {
            if (mode == YencCrcValidationMode.WhenPresent)
            {
                return;
            }

            throw new InvalidDataException(
                $"The yEnc trailer does not contain a valid {Encoding.ASCII.GetString(fieldName)} value.");
        }

        if (actualCrc32 != expectedCrc32)
        {
            throw new InvalidDataException(
                $"The decoded yEnc CRC32 was {actualCrc32:x8}, but the trailer expected {expectedCrc32:x8}.");
        }
    }

    private static bool TryParseYencTrailerCrc32(
        ReadOnlySpan<byte> trailer,
        ReadOnlySpan<byte> fieldName,
        out uint crc32)
    {
        var position = 0;
        while (position < trailer.Length)
        {
            while (position < trailer.Length && IsAsciiWhitespace(trailer[position]))
            {
                position++;
            }

            var tokenStart = position;
            while (position < trailer.Length && !IsAsciiWhitespace(trailer[position]))
            {
                position++;
            }

            var token = trailer[tokenStart..position];
            var separator = token.IndexOf((byte)'=');
            if (separator <= 0 ||
                !AsciiEqualsIgnoreCase(token[..separator], fieldName))
            {
                continue;
            }

            var value = token[(separator + 1)..];
            return Utf8Parser.TryParse(value, out crc32, out var consumed, 'X') &&
                consumed == value.Length;
        }

        crc32 = 0;
        return false;
    }

    private static bool AsciiEqualsIgnoreCase(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        for (var index = 0; index < left.Length; index++)
        {
            var leftValue = left[index];
            var rightValue = right[index];
            if (leftValue is >= (byte)'A' and <= (byte)'Z')
            {
                leftValue += (byte)('a' - 'A');
            }

            if (rightValue is >= (byte)'A' and <= (byte)'Z')
            {
                rightValue += (byte)('a' - 'A');
            }

            if (leftValue != rightValue)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAsciiWhitespace(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';
}
