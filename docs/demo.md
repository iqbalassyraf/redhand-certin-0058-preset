# Demo: CRAFTY FALCON, enforce vs observe-only

A recording of `examples/simulate_crafty_falcon.py` running the four kill-chain stages of
CIAD-2026-0058 through the real shield with stub tools. Synthetic calls only; nothing leaves the
process. The first pass is observe-only (everything runs, every `would_have_blocked` is recorded),
the second is enforce. It ends by verifying the audit chain and detecting a forged line.

<div id="player" class="player">
<div class="term" role="log" aria-label="Terminal recording of the simulation"></div>
<div class="controls">
<button type="button" data-play>Play</button>
<button type="button" data-restart>Restart</button>
<label>Speed <select data-speed><option value="1">1x</option><option value="2">2x</option><option value="4">4x</option></select></label>
<input type="range" min="0" max="100" value="0" data-seek aria-label="Seek">
<span data-clock>0.0 / 0.0 s</span>
</div>
</div>

Without JavaScript, or on a page that strips scripts, use the transcript below or download the
recording: [crafty_falcon.cast](demo/crafty_falcon.cast) (asciicast v2, plays with `asciinema play`) and
[crafty_falcon.txt](demo/crafty_falcon.txt).

## Run it yourself

```bash
pip install "redhand-certin-0058-preset[demo]"
python examples/simulate_crafty_falcon.py --delay 0
```

The latency figures in the recording are real measurements from the machine that recorded it.
They vary a little on every run; the decisions do not.

## Transcript

{{TRANSCRIPT}}
