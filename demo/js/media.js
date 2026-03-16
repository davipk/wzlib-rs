import { state } from './state.js';
import { formatBytes, decodeCanvasResult } from './utils.js';
import { dispatchDecodeCanvas, dispatchExtractSound, dispatchExtractVideo } from './wasm-dispatch.js';

// ── Canvas preview ───────────────────────────────────────────────────

export function loadCanvasPreview(holder, imgOffset, propPath, width, height, depth) {
  setTimeout(() => {
    try {
      const result = dispatchDecodeCanvas(imgOffset, propPath);
      const { w, h, rgba } = decodeCanvasResult(result);

      const cvs = document.createElement('canvas');
      cvs.width = w;
      cvs.height = h;
      const ctx = cvs.getContext('2d');
      const imgData = new ImageData(new Uint8ClampedArray(rgba.buffer, rgba.byteOffset, rgba.byteLength), w, h);
      ctx.putImageData(imgData, 0, 0);

      const wrapper = document.createElement('div');
      wrapper.className = 'canvas-preview';
      wrapper.style.setProperty('--pdepth', depth);
      wrapper.title = `${w}x${h} — click to toggle size`;

      const isSprite = w <= 200 && h <= 200;
      if (isSprite) wrapper.classList.add('pixelated');

      wrapper.appendChild(cvs);

      const renderToggle = document.createElement('button');
      renderToggle.className = 'render-toggle';
      renderToggle.textContent = isSprite ? 'smooth' : 'pixel';
      renderToggle.title = 'Toggle rendering mode';
      renderToggle.addEventListener('click', (e) => {
        e.stopPropagation();
        wrapper.classList.toggle('pixelated');
        renderToggle.textContent = wrapper.classList.contains('pixelated') ? 'smooth' : 'pixel';
      });
      wrapper.appendChild(renderToggle);

      wrapper.addEventListener('click', (e) => {
        e.stopPropagation();
        wrapper.classList.toggle('expanded');
      });

      holder.replaceWith(wrapper);
    } catch (e) {
      holder.textContent = `Decode error: ${e.message}`;
      holder.style.color = 'var(--accent)';
      console.error('Canvas decode error:', e);
    }
  }, 10);
}

// ── Sound player ─────────────────────────────────────────────────────

export function loadSoundPlayer(holder, imgOffset, propPath, durationMs, depth) {
  setTimeout(() => {
    try {
      const audioBytes = dispatchExtractSound(imgOffset, propPath);

      const blob = new Blob([audioBytes], { type: 'audio/mpeg' });
      const url = URL.createObjectURL(blob);

      const wrapper = document.createElement('div');
      wrapper.className = 'sound-player';
      wrapper.style.setProperty('--pdepth', depth);

      const playBtn = document.createElement('button');
      playBtn.textContent = '\u25B6 Play';

      const stopBtn = document.createElement('button');
      stopBtn.textContent = '\u25A0 Stop';
      stopBtn.disabled = true;

      const info = document.createElement('span');
      info.className = 'sound-info';
      info.textContent = `${(durationMs / 1000).toFixed(1)}s \u00B7 ${formatBytes(audioBytes.length)}`;

      const audio = new Audio(url);

      playBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (state.currentAudio && state.currentAudio !== audio) {
          state.currentAudio.pause();
          state.currentAudio.currentTime = 0;
          if (state.currentPlayBtn) state.currentPlayBtn.disabled = false;
          if (state.currentStopBtn) state.currentStopBtn.disabled = true;
        }
        state.currentAudio = audio;
        state.currentPlayBtn = playBtn;
        state.currentStopBtn = stopBtn;
        audio.play();
        playBtn.disabled = true;
        stopBtn.disabled = false;
      });

      stopBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        audio.pause();
        audio.currentTime = 0;
        playBtn.disabled = false;
        stopBtn.disabled = true;
      });

      audio.addEventListener('ended', () => {
        playBtn.disabled = false;
        stopBtn.disabled = true;
      });

      audio.addEventListener('error', () => {
        info.textContent = `${(durationMs / 1000).toFixed(1)}s \u00B7 format not supported by browser`;
        info.style.color = 'var(--accent)';
        playBtn.disabled = true;
      });

      const volLabel = document.createElement('span');
      volLabel.className = 'vol-label';
      volLabel.textContent = '100%';

      const volSlider = document.createElement('input');
      volSlider.type = 'range';
      volSlider.min = '0';
      volSlider.max = '100';
      volSlider.value = '100';
      volSlider.title = 'Volume';
      volSlider.addEventListener('input', (e) => {
        e.stopPropagation();
        const v = volSlider.value / 100;
        audio.volume = v;
        volLabel.textContent = `${volSlider.value}%`;
      });
      volSlider.addEventListener('click', (e) => e.stopPropagation());

      wrapper.appendChild(playBtn);
      wrapper.appendChild(stopBtn);
      wrapper.appendChild(volSlider);
      wrapper.appendChild(volLabel);
      wrapper.appendChild(info);
      holder.replaceWith(wrapper);
    } catch (e) {
      holder.textContent = `Audio error: ${e.message}`;
      holder.style.color = 'var(--accent)';
      console.error('Sound extract error:', e);
    }
  }, 10);
}

// ── Video download ───────────────────────────────────────────────────

export function loadVideoDownload(holder, imgOffset, propPath, prop, depth) {
  setTimeout(() => {
    try {
      const videoBytes = dispatchExtractVideo(imgOffset, propPath);

      const wrapper = document.createElement('div');
      wrapper.className = 'sound-player'; // reuse sound-player layout
      wrapper.style.setProperty('--pdepth', depth);

      const dlBtn = document.createElement('button');
      dlBtn.textContent = '\u2B07 Download';
      dlBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const blob = new Blob([videoBytes], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${prop.name || 'video'}.mcv`;
        a.click();
        URL.revokeObjectURL(url);
      });

      const info = document.createElement('span');
      info.className = 'sound-info';
      let desc = formatBytes(videoBytes.length);
      if (prop.mcv) {
        desc = `${prop.mcv.width}x${prop.mcv.height} ${prop.mcv.frameCount}f \u00B7 ${desc}`;
      }
      info.textContent = desc;

      wrapper.appendChild(dlBtn);
      wrapper.appendChild(info);
      holder.replaceWith(wrapper);
    } catch (e) {
      holder.textContent = `Video error: ${e.message}`;
      holder.style.color = 'var(--accent)';
      console.error('Video extract error:', e);
    }
  }, 10);
}

// ── Animation player ─────────────────────────────────────────────────

export function getCanvasAnimFrames(prop) {
  if (!prop.children || prop.children.length < 2) return null;
  let start = -1;
  for (const c of prop.children) {
    const n = parseInt(c.name, 10);
    if (!isNaN(n) && String(n) === String(c.name) && c.type === 'Canvas') {
      if (start === -1 || n < start) start = n;
    }
  }
  if (start === -1) return null;
  const frames = [];
  for (let i = start; ; i++) {
    const child = prop.children.find(c => String(c.name) === String(i));
    if (!child || child.type !== 'Canvas') break;
    frames.push(child);
  }
  return frames.length >= 2 ? frames : null;
}

export function createAnimPlayer(frames, imgOffset, parentPath, depth) {
  const player = document.createElement('div');
  player.className = 'anim-player';
  player.style.setProperty('--pdepth', depth);

  let maxW = 0, maxH = 0;
  for (const f of frames) {
    if (f.width > maxW) maxW = f.width;
    if (f.height > maxH) maxH = f.height;
  }

  const canvasWrap = document.createElement('div');
  canvasWrap.className = 'anim-canvas-wrap';
  if (maxW <= 200 && maxH <= 200) canvasWrap.classList.add('pixelated');
  const cvs = document.createElement('canvas');
  cvs.width = maxW;
  cvs.height = maxH;
  canvasWrap.appendChild(cvs);
  player.appendChild(canvasWrap);

  const controls = document.createElement('div');
  controls.className = 'anim-controls';

  const playBtn = document.createElement('button');
  playBtn.textContent = '\u25B6 Play';
  const stopBtn = document.createElement('button');
  stopBtn.textContent = '\u25A0 Stop';
  stopBtn.disabled = true;

  const frameInfo = document.createElement('span');
  frameInfo.className = 'anim-frame';
  frameInfo.textContent = `${frames.length} frames`;

  const delayLabel = document.createElement('label');
  delayLabel.textContent = 'Delay: ';
  const delayInput = document.createElement('input');
  delayInput.type = 'number';
  delayInput.value = '100';
  delayInput.min = '10';
  delayInput.max = '5000';
  delayInput.step = '10';
  delayLabel.appendChild(delayInput);
  delayLabel.appendChild(document.createTextNode(' ms'));

  controls.append(playBtn, stopBtn, frameInfo, delayLabel);
  player.appendChild(controls);

  const frameCache = new Map();
  let animTimer = null;
  let currentFrame = 0;
  let playing = false;
  let initialized = false;

  function decodeFrame(idx) {
    if (frameCache.has(idx)) return frameCache.get(idx);
    const frame = frames[idx];
    const path = parentPath ? `${parentPath}/${frame.name}` : frame.name;
    const result = dispatchDecodeCanvas(imgOffset, path);
    const data = decodeCanvasResult(result);
    frameCache.set(idx, data);
    return data;
  }

  function showFrame(idx) {
    try {
      const { w, h, rgba } = decodeFrame(idx);
      cvs.width = maxW;
      cvs.height = maxH;
      const ctx = cvs.getContext('2d');
      ctx.clearRect(0, 0, maxW, maxH);
      const imgData = new ImageData(new Uint8ClampedArray(rgba.buffer, rgba.byteOffset, rgba.byteLength), w, h);
      const ox = Math.floor((maxW - w) / 2);
      const oy = Math.floor((maxH - h) / 2);
      ctx.putImageData(imgData, ox, oy);
      frameInfo.textContent = `${idx + 1} / ${frames.length}`;
    } catch (e) {
      frameInfo.textContent = `Frame ${idx} error`;
      console.error('Anim decode error:', e);
    }
  }

  function play() {
    if (playing) return;
    playing = true;
    playBtn.textContent = '\u23F8 Pause';
    stopBtn.disabled = false;
    tick();
  }

  function tick() {
    showFrame(currentFrame);
    currentFrame = (currentFrame + 1) % frames.length;
    const delay = Math.max(10, parseInt(delayInput.value) || 100);
    animTimer = setTimeout(tick, delay);
  }

  function pause() {
    playing = false;
    playBtn.textContent = '\u25B6 Play';
    if (animTimer) { clearTimeout(animTimer); animTimer = null; }
  }

  function stop() {
    pause();
    currentFrame = 0;
    showFrame(0);
    stopBtn.disabled = true;
  }

  playBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (playing) pause();
    else play();
  });

  stopBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    stop();
  });

  delayInput.addEventListener('click', (e) => e.stopPropagation());
  delayInput.addEventListener('keydown', (e) => e.stopPropagation());

  player._anim = {
    init() {
      if (initialized) return;
      initialized = true;
      state.activeAnimControllers.push(player._anim);
      showFrame(0);
    },
    destroy() {
      pause();
    }
  };

  return player;
}
