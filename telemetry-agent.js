(() => {
  const endpoint = "/api/telemetry";
  const state = {
    startedAt: Date.now(),
    pointer: [],
    touch: [],
    motion: [],
    scroll: [],
    heartbeatCount: 0
  };

  const safePush = (arr, item, limit = 120) => {
    arr.push(item);
    if (arr.length > limit) arr.shift();
  };

  const capturePointer = (event) => {
    safePush(state.pointer, {
      x: Math.round(event.clientX || 0),
      y: Math.round(event.clientY || 0),
      t: performance.now(),
      type: event.type
    });
  };

  const captureTouch = (event) => {
    const touch = event.touches && event.touches[0];
    if (!touch) return;
    safePush(state.touch, {
      x: Math.round(touch.clientX || 0),
      y: Math.round(touch.clientY || 0),
      t: performance.now(),
      type: event.type
    });
  };

  const captureScroll = () => {
    safePush(state.scroll, {
      x: Math.round(window.scrollX || 0),
      y: Math.round(window.scrollY || 0),
      t: performance.now()
    }, 60);
  };

  const tryMotion = async () => {
    try {
      if (typeof DeviceMotionEvent !== "undefined" && typeof DeviceMotionEvent.requestPermission === "function") {
        const status = await DeviceMotionEvent.requestPermission().catch(() => "denied");
        if (status !== "granted") return;
      }
      window.addEventListener("devicemotion", (event) => {
        safePush(state.motion, {
          ax: Number(event.acceleration?.x || 0),
          ay: Number(event.acceleration?.y || 0),
          az: Number(event.acceleration?.z || 0),
          rx: Number(event.rotationRate?.alpha || 0),
          ry: Number(event.rotationRate?.beta || 0),
          rz: Number(event.rotationRate?.gamma || 0),
          interval: Number(event.interval || 0),
          t: performance.now()
        }, 80);
      });
    } catch {}
  };

  const hashHex = async (input) => {
    const data = new TextEncoder().encode(input);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  };

  const canvasFingerprint = async () => {
    try {
      const canvas = document.createElement("canvas");
      canvas.width = 240;
      canvas.height = 80;
      const ctx = canvas.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "16px Arial";
      ctx.fillStyle = "#f60";
      ctx.fillRect(20, 10, 100, 30);
      ctx.fillStyle = "#069";
      ctx.fillText("ASO Shield Telemetry", 10, 40);
      return await hashHex(canvas.toDataURL());
    } catch {
      return null;
    }
  };

  const webglFingerprint = async () => {
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) return null;
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      const vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : "unknown";
      const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : "unknown";
      return await hashHex(`${vendor}|${renderer}|${gl.getParameter(gl.VERSION)}`);
    } catch {
      return null;
    }
  };

  const audioFingerprint = async () => {
    try {
      const AudioCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!AudioCtx) return null;
      const ctx = new AudioCtx(1, 44100, 44100);
      const oscillator = ctx.createOscillator();
      const compressor = ctx.createDynamicsCompressor();
      oscillator.type = "triangle";
      oscillator.frequency.value = 10000;
      oscillator.connect(compressor);
      compressor.connect(ctx.destination);
      oscillator.start(0);
      const rendered = await ctx.startRendering();
      const samples = rendered.getChannelData(0).slice(4500, 5000);
      return await hashHex(Array.from(samples).join(","));
    } catch {
      return null;
    }
  };

  const buildPayload = async () => {
    const [canvasHash, webglHash, audioHash] = await Promise.all([
      canvasFingerprint(),
      webglFingerprint(),
      audioFingerprint()
    ]);
    return {
      ts: Date.now(),
      url: location.pathname,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown",
      lang: navigator.language || "unknown",
      ua: navigator.userAgent || "unknown",
      platform: navigator.platform || "unknown",
      webdriver: !!navigator.webdriver,
      hw: navigator.hardwareConcurrency || null,
      mem: navigator.deviceMemory || null,
      screen: {
        w: window.screen?.width || null,
        h: window.screen?.height || null,
        dpr: window.devicePixelRatio || 1
      },
      fp: {
        canvasHash,
        webglHash,
        audioHash
      },
      behavior: {
        telemetryVersion: "enterprise-plus-final",
        pointer: state.pointer,
        touch: state.touch,
        motion: state.motion,
        scroll: state.scroll,
        dwellMs: Date.now() - state.startedAt,
        heartbeatCount: state.heartbeatCount
      }
    };
  };

  const flush = async () => {
    try {
      const payload = await buildPayload();
      navigator.sendBeacon(endpoint, new Blob([JSON.stringify(payload)], { type: "application/json" }));
    } catch {}
  };

  window.addEventListener("mousemove", capturePointer, { passive: true });
  window.addEventListener("mousedown", capturePointer, { passive: true });
  window.addEventListener("mouseup", capturePointer, { passive: true });
  window.addEventListener("touchstart", captureTouch, { passive: true });
  window.addEventListener("touchmove", captureTouch, { passive: true });
  window.addEventListener("scroll", captureScroll, { passive: true });
  window.addEventListener("beforeunload", flush);

  setInterval(() => {
    state.heartbeatCount += 1;
    flush();
  }, 15000);

  tryMotion();
})();


window.__asoGetLatestTelemetry = async function () {
  try {
    const dummy = await (async () => {
      const data = {
        ts: Date.now(),
        ua: navigator.userAgent || "unknown",
        fp: {}
      };
      return data;
    })();
    return dummy;
  } catch {
    return { ts: Date.now(), ua: navigator.userAgent || "unknown", fp: {} };
  }
};


(function(){
  const oldBuild = window.__asoGetLatestTelemetry;
  window.__asoGetLatestTelemetry = async function () {
    try {
      const base = await oldBuild();
      const out = { ...base, url: location.pathname, ua: navigator.userAgent || "unknown", fp: base.fp || {} };
      window.__asoLastTelemetry = out;
      return out;
    } catch {
      const out = { url: location.pathname, ua: navigator.userAgent || "unknown", fp: {} };
      window.__asoLastTelemetry = out;
      return out;
    }
  };
  setInterval(() => { window.__asoGetLatestTelemetry().catch(() => {}); }, 3000);
})();
