// Losslessly join the kept time ranges of a movie (passthrough export, no re-encode).
// usage: splicevideo IN OUT start1-end1 [start2-end2 ...]   (seconds)
import AVFoundation
let a = CommandLine.arguments
let asset = AVURLAsset(url: URL(fileURLWithPath: a[1]))
let comp = AVMutableComposition()
var cursor = CMTime.zero
for spec in a.dropFirst(3) {
    let p = spec.split(separator: "-").map { Double($0)! }
    let r = CMTimeRange(start: CMTime(seconds: p[0], preferredTimescale: 600),
                        end: CMTime(seconds: p[1], preferredTimescale: 600))
    do { try comp.insertTimeRange(r, of: asset, at: cursor) } catch { print("FAIL insert \(error)"); exit(1) }
    cursor = cursor + r.duration
}
guard let ex = AVAssetExportSession(asset: comp, presetName: AVAssetExportPresetPassthrough) else { print("FAIL session"); exit(1) }
ex.outputURL = URL(fileURLWithPath: a[2])
ex.outputFileType = a[2].lowercased().hasSuffix(".mp4") ? .mp4 : .mov
let sem = DispatchSemaphore(value: 0)
ex.exportAsynchronously { sem.signal() }
sem.wait()
print(ex.status == .completed ? "OK" : "FAIL \(String(describing: ex.error))")
