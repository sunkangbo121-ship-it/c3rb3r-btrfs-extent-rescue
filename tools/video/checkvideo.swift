// Fully decode every video frame and read every audio sample of a movie; report failures.
// usage: swift checkvideo.swift FILE [FILE...]
import AVFoundation

func check(_ path: String) -> String {
    let asset = AVURLAsset(url: URL(fileURLWithPath: path))
    let sem = DispatchSemaphore(value: 0)
    var tracks: [AVAssetTrack] = []
    var duration = CMTime.zero
    var loadError: Error?
    Task {
        do {
            tracks = try await asset.load(.tracks)
            duration = try await asset.load(.duration)
        } catch { loadError = error }
        sem.signal()
    }
    sem.wait()
    if let e = loadError { return "FAIL load: \(e.localizedDescription)" }
    // one reader per track, so a stalled sibling output cannot fail the read
    var counts: [String: String] = [:]
    var failed = false
    for t in tracks where t.mediaType == .video || t.mediaType == .audio {
        guard let reader = try? AVAssetReader(asset: asset) else { return "FAIL reader" }
        let settings: [String: Any] = t.mediaType == .video
            ? [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange]
            : [AVFormatIDKey: kAudioFormatLinearPCM]
        let o = AVAssetReaderTrackOutput(track: t, outputSettings: settings)
        reader.add(o)
        guard reader.startReading() else { return "FAIL start: \(reader.error?.localizedDescription ?? "?")" }
        var n = 0
        var last = CMTime.zero
        while let sb = o.copyNextSampleBuffer() { n += 1; last = CMSampleBufferGetPresentationTimeStamp(sb) }
        let ok = reader.status != .failed
        if !ok { failed = true }
        counts["\(t.mediaType.rawValue)#\(t.trackID)"] = String(format: "%d samples to %.2fs%@", n, last.seconds, ok ? "" : " FAILED(\(reader.error?.localizedDescription ?? "?"))")
    }
    if failed { return String(format: "FAIL duration=%.2fs ", duration.seconds) + "\(counts)" }
    return String(format: "OK duration=%.2fs ", duration.seconds) + "\(counts)"
}

for p in CommandLine.arguments.dropFirst() {
    print("\(check(p))\t\(p)")
}
