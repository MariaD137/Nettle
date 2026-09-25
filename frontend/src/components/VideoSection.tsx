import { useRef, useState } from "react";

// Served from public/ (not bundled) so the video payload never enters the
// JS bundle and can be swapped without a rebuild. This cut already has its
// captions burned into the picture, so there's no <track> element below —
// a WebVTT overlay on top would just double them up. CAPTIONS_SRC is kept
// only as a downloadable plain-text transcript for the link at the bottom.
const VIDEO_SRC = "/media/nettle-explainer.mp4";
const POSTER_SRC = "/media/nettle-explainer-poster.jpg";
const CAPTIONS_SRC = "/media/nettle-explainer.vtt";

/**
 * Click-to-play only — never autoplay, muted or otherwise. `preload="none"`
 * means the browser fetches nothing but the (lightweight, vector) poster
 * until the visitor actually presses play, so the video's own weight never
 * counts against the landing page's load time. The poster's fixed
 * aspect-ratio on the wrapping frame reserves the video's layout space
 * before either asset loads, so there's no layout shift either way.
 */
export default function VideoSection() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [playing, setPlaying] = useState(false);

  const play = () => {
    videoRef.current?.play();
  };

  return (
    <section className="marketing-section video-section" aria-labelledby="video-section-title">
      <h2 id="video-section-title" className="marketing-section-title">
        See Nettle in 30 seconds
      </h2>
      <p className="muted marketing-section-sub">
        AI can build your app fast. Here's what Nettle does about the part that isn't ready yet.
      </p>

      <div className="video-frame">
        <video
          ref={videoRef}
          className="video-player"
          poster={POSTER_SRC}
          controls={playing}
          preload="none"
          playsInline
          onPlay={() => setPlaying(true)}
          onPause={() => setPlaying(false)}
          onEnded={() => setPlaying(false)}
        >
          <source src={VIDEO_SRC} type="video/mp4" />
          Your browser doesn't support embedded video.{" "}
          <a href={VIDEO_SRC}>Download the video</a> instead.
        </video>

        {!playing && (
          <button
            type="button"
            className="video-play-button"
            onClick={play}
            aria-label="Play: how Nettle scans, explains, and fixes AI-built app gaps (30 seconds)"
          >
            <svg width="22" height="26" viewBox="0 0 22 26" aria-hidden="true">
              <path d="M0 0 L22 13 L0 26 Z" fill="currentColor" />
            </svg>
          </button>
        )}
      </div>

      <p className="muted video-transcript-link">
        <a href={CAPTIONS_SRC}>Read the transcript</a>
      </p>
    </section>
  );
}
