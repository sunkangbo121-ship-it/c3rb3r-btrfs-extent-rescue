// Losslessly cut a movie to [0, SECONDS) with a passthrough export (no re-encode).
// usage: swift trimvideo.swift IN OUT SECONDS
import AVFoundation
let a = CommandLine.arguments
let asset = AVURLAsset(url: URL(fileURLWithPath: a[1]))
guard let ex = AVAssetExportSession(asset: asset, presetName: AVAssetExportPresetPassthrough) else { print("FAIL session"); exit(1) }
ex.outputURL = URL(fileURLWithPath: a[2])
ex.outputFileType = a[2].lowercased().hasSuffix(".mp4") ? .mp4 : .mov
ex.timeRange = CMTimeRange(start: .zero, duration: CMTime(seconds: Double(a[3])!, preferredTimescale: 600))
let sem = DispatchSemaphore(value: 0)
ex.exportAsynchronously { sem.signal() }
sem.wait()
print(ex.status == .completed ? "OK" : "FAIL \(ex.error?.localizedDescription ?? "?")")
