from flask import Flask, render_template_string, request
from PIL import Image
import io
import base64

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>8-Bit Mona Lisa Studio</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #1a1a1a;
            color: #eee;
            text-align: center;
            padding: 20px;
        }
        .workspace {
            display: flex;
            gap: 30px;
            justify-content: center;
            flex-wrap: wrap;
            max-width: 1600px;
            margin: 0 auto;
        }
        .panel {
            background: #2a2a2a;
            padding: 20px;
            border-radius: 15px;
        }
        .reference-panel {
            flex: 1;
            min-width: 300px;
        }
        .converter-panel {
            flex: 1;
            min-width: 300px;
        }
        .canvas-panel {
            flex: 2;
            min-width: 500px;
        }
        .reference-img, .converted-img {
            max-width: 100%;
            max-height: 300px;
            border: 3px solid #444;
            border-radius: 5px;
            margin: 10px 0;
            image-rendering: pixelated;
        }
        .pixel-canvas {
            display: grid;
            grid-template-columns: repeat(32, 20px);
            gap: 1px;
            justify-content: center;
            margin: 20px auto;
            background: #1a1a1a;
            padding: 10px;
            border-radius: 5px;
        }
        .pixel {
            width: 20px;
            height: 20px;
            background-color: #8B7355;
            border: 1px solid #333;
            cursor: pointer;
            transition: transform 0.1s;
        }
        .pixel:hover {
            transform: scale(1.2);
            z-index: 10;
            border: 1px solid gold;
        }
        .palette {
            display: flex;
            gap: 10px;
            justify-content: center;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        .color-swatch {
            width: 40px;
            height: 40px;
            border-radius: 5px;
            cursor: pointer;
            border: 3px solid #444;
            transition: all 0.2s;
        }
        .color-swatch.selected {
            border: 3px solid gold;
            transform: scale(1.1);
        }
        .tools {
            margin: 20px 0;
            display: flex;
            gap: 10px;
            justify-content: center;
            flex-wrap: wrap;
        }
        .tool-btn {
            background: #333;
            color: white;
            border: 1px solid #555;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
        }
        .tool-btn:hover {
            background: #444;
            border-color: gold;
        }
        .tool-btn.active {
            background: gold;
            color: black;
            border-color: white;
        }
        .slider-group {
            background: #333;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
        }
        input[type=range] {
            width: 100%;
            margin: 10px 0;
        }
        .action-btn {
            background: #ffd700;
            color: #1a1a1a;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin: 5px;
        }
        .action-btn:hover {
            background: #ffed4a;
        }
        .stats {
            font-size: 0.9em;
            color: #aaa;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <h1>8-Bit Mona Lisa Studio</h1>
    <p>1. Upload a photo &rarr; 2. Auto-convert to 8-bit &rarr; 3. Refine by hand</p>

    <div class="workspace">
        <!-- Reference Panel -->
        <div class="panel reference-panel">
            <h3>Step 1: Source Image</h3>

            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="photo" accept="image/*" required>
                <button type="submit" class="action-btn">Upload</button>
            </form>

            {% if original %}
                <h4>Original</h4>
                <img src="data:image/png;base64,{{ original }}" class="reference-img">
            {% else %}
                <div style="background: #333; padding: 40px; border-radius: 5px; margin: 20px 0;">
                    <p>No image yet</p>
                </div>
            {% endif %}
        </div>

        <!-- Converter Panel -->
        <div class="panel converter-panel">
            <h3>Step 2: Auto 8-Bit</h3>

            {% if original %}
            <form action="/convert" method="post">
                <input type="hidden" name="original_data" value="{{ original }}">

                <div class="slider-group">
                    <label>Pixel Size (8-bit chunkiness)</label>
                    <input type="range" name="pixel_size" min="4" max="64" value="{{ pixel_size or 16 }}" onchange="this.form.submit()">
                    <div>Current: <span id="pixelVal">{{ pixel_size or 16 }}</span>px blocks</div>
                </div>

                <div class="slider-group">
                    <label>Color Count</label>
                    <input type="range" name="color_count" min="2" max="32" value="{{ color_count or 16 }}" onchange="this.form.submit()">
                    <div>Current: <span id="colorVal">{{ color_count or 16 }}</span> colors</div>
                </div>

                <button type="submit" class="action-btn">Convert to 8-Bit</button>
            </form>

            {% if converted %}
                <h4>8-Bit Result</h4>
                <img src="data:image/png;base64,{{ converted }}" class="converted-img">

                <div class="stats">
                    {{ width }} x {{ height }} pixels &bull; {{ color_count or 16 }} colors
                </div>

                <button class="action-btn" onclick="loadToCanvas('{{ converted }}')">Load into Canvas</button>
            {% endif %}

            {% else %}
                <p style="color: #666;">Upload an image first</p>
            {% endif %}
        </div>

        <!-- Canvas Panel -->
        <div class="panel canvas-panel">
            <h3>Step 3: Your 8-Bit Masterpiece</h3>

            <div class="palette" id="palette">
                <div class="color-swatch" style="background: #F2D2B6;" onclick="selectColor('#F2D2B6')" title="Skin"></div>
                <div class="color-swatch" style="background: #D4A76A;" onclick="selectColor('#D4A76A')" title="Highlight"></div>
                <div class="color-swatch" style="background: #8B5A2B;" onclick="selectColor('#8B5A2B')" title="Shadow"></div>
                <div class="color-swatch" style="background: #4A2511;" onclick="selectColor('#4A2511')" title="Dark hair"></div>
                <div class="color-swatch" style="background: #2C1810;" onclick="selectColor('#2C1810')" title="Eyes"></div>
                <div class="color-swatch" style="background: #B85C3A;" onclick="selectColor('#B85C3A')" title="Lips"></div>
                <div class="color-swatch" style="background: #5D7A5C;" onclick="selectColor('#5D7A5C')" title="Background"></div>
                <div class="color-swatch" style="background: #000000;" onclick="selectColor('#000000')" title="Black"></div>
            </div>

            <div class="tools">
                <button class="tool-btn active" id="pencilBtn" onclick="setTool('pencil')">Pencil</button>
                <button class="tool-btn" id="fillBtn" onclick="setTool('fill')">Fill</button>
                <button class="tool-btn" id="eyedropperBtn" onclick="setTool('eyedropper')">Dropper</button>
                <button class="tool-btn" onclick="clearCanvas()">Clear</button>
                <button class="tool-btn" onclick="saveArt()">Save</button>
            </div>

            <div class="pixel-canvas" id="pixelCanvas">
                {% for row in range(32) %}
                    {% for col in range(32) %}
                    <div class="pixel"
                         id="pixel-{{ row }}-{{ col }}"
                         data-row="{{ row }}"
                         data-col="{{ col }}"
                         style="background-color: #F2D2B6;"
                         onclick="handlePixelClick(this)"
                         onmouseover="handlePixelHover(this)"
                         onmousedown="event.preventDefault()"></div>
                    {% endfor %}
                {% endfor %}
            </div>

            <div id="coord-display" style="margin-top: 10px; color: #888;">Hover over a pixel</div>
        </div>
    </div>

    <script>
        let currentColor = '#F2D2B6';
        let currentTool = 'pencil';
        let isDrawing = false;

        document.addEventListener('mousedown', () => isDrawing = true);
        document.addEventListener('mouseup', () => isDrawing = false);
        document.addEventListener('mouseleave', () => isDrawing = false);

        function selectColor(color) {
            currentColor = color;
            document.querySelectorAll('.color-swatch').forEach(s => s.classList.remove('selected'));
            event.target.classList.add('selected');
            if (currentTool === 'eyedropper') setTool('pencil');
        }

        function setTool(tool) {
            currentTool = tool;
            document.querySelectorAll('.tool-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById(tool + 'Btn').classList.add('active');
        }

        function handlePixelClick(pixel) {
            if (currentTool === 'pencil') {
                pixel.style.backgroundColor = currentColor;
            } else if (currentTool === 'fill') {
                floodFill(pixel);
            } else if (currentTool === 'eyedropper') {
                pickColor(pixel);
            }
        }

        function handlePixelHover(pixel) {
            const row = pixel.dataset.row;
            const col = pixel.dataset.col;
            document.getElementById('coord-display').textContent =
                'Pixel: (' + row + ', ' + col + ') - Color: ' + pixel.style.backgroundColor;

            if (isDrawing && currentTool === 'pencil') {
                pixel.style.backgroundColor = currentColor;
            }
        }

        function pickColor(pixel) {
            const color = pixel.style.backgroundColor;
            if (color) {
                currentColor = rgbToHex(color);
                selectColor(currentColor);
            }
        }

        function rgbToHex(rgb) {
            const match = rgb.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/);
            if (!match) return currentColor;
            const r = parseInt(match[1]).toString(16).padStart(2, '0');
            const g = parseInt(match[2]).toString(16).padStart(2, '0');
            const b = parseInt(match[3]).toString(16).padStart(2, '0');
            return '#' + r + g + b;
        }

        function floodFill(pixel) {
            const targetColor = pixel.style.backgroundColor;
            if (targetColor === currentColor) return;

            const queue = [pixel];
            const visited = new Set();

            while (queue.length) {
                const current = queue.shift();
                if (!current || visited.has(current)) continue;

                visited.add(current);

                if (current.style.backgroundColor === targetColor) {
                    current.style.backgroundColor = currentColor;

                    const row = parseInt(current.dataset.row);
                    const col = parseInt(current.dataset.col);

                    const neighbors = [
                        document.getElementById('pixel-' + (row-1) + '-' + col),
                        document.getElementById('pixel-' + (row+1) + '-' + col),
                        document.getElementById('pixel-' + row + '-' + (col-1)),
                        document.getElementById('pixel-' + row + '-' + (col+1))
                    ];

                    neighbors.forEach(n => n && !visited.has(n) && queue.push(n));
                }
            }
        }

        function loadToCanvas(base64Data) {
            const img = new Image();
            img.onload = function() {
                const tempCanvas = document.createElement('canvas');
                tempCanvas.width = 32;
                tempCanvas.height = 32;
                const ctx = tempCanvas.getContext('2d');
                ctx.drawImage(img, 0, 0, 32, 32);

                const imageData = ctx.getImageData(0, 0, 32, 32);
                const data = imageData.data;

                for (let row = 0; row < 32; row++) {
                    for (let col = 0; col < 32; col++) {
                        const i = (row * 32 + col) * 4;
                        const r = data[i];
                        const g = data[i + 1];
                        const b = data[i + 2];
                        const hex = '#' + [r, g, b].map(x => x.toString(16).padStart(2, '0')).join('');

                        const pixel = document.getElementById('pixel-' + row + '-' + col);
                        if (pixel) pixel.style.backgroundColor = hex;
                    }
                }
            };
            img.src = 'data:image/png;base64,' + base64Data;
        }

        function clearCanvas() {
            if (confirm('Clear your canvas?')) {
                document.querySelectorAll('.pixel').forEach(p => {
                    p.style.backgroundColor = '#F2D2B6';
                });
            }
        }

        function saveArt() {
            const canvas = document.createElement('canvas');
            canvas.width = 320;
            canvas.height = 320;
            const ctx = canvas.getContext('2d');

            document.querySelectorAll('.pixel').forEach(pixel => {
                const row = parseInt(pixel.dataset.row);
                const col = parseInt(pixel.dataset.col);
                ctx.fillStyle = pixel.style.backgroundColor;
                ctx.fillRect(col * 10, row * 10, 10, 10);
            });

            const link = document.createElement('a');
            link.download = 'my-8bit-mona.png';
            link.href = canvas.toDataURL();
            link.click();
        }
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/upload', methods=['POST'])
def upload():
    if 'photo' in request.files:
        file = request.files['photo']
        img = Image.open(file.stream).convert('RGB')

        orig_buf = io.BytesIO()
        img.save(orig_buf, format='PNG')
        orig_base64 = base64.b64encode(orig_buf.getvalue()).decode('utf-8')

        return render_template_string(HTML, original=orig_base64)

    return index()


@app.route('/convert', methods=['POST'])
def convert():
    original_data = request.form.get('original_data')
    pixel_size = int(request.form.get('pixel_size', 16))
    color_count = int(request.form.get('color_count', 16))

    if original_data:
        img_data = base64.b64decode(original_data)
        img = Image.open(io.BytesIO(img_data)).convert('RGB')

        width, height = img.size

        small_w = max(1, width // pixel_size)
        small_h = max(1, height // pixel_size)
        pixelated_small = img.resize((small_w, small_h), resample=Image.NEAREST)

        paletted = pixelated_small.convert('P', palette=Image.ADAPTIVE, colors=color_count)
        color_reduced = paletted.convert('RGB')

        pixelated = color_reduced.resize((width, height), resample=Image.NEAREST)

        conv_buf = io.BytesIO()
        pixelated.save(conv_buf, format='PNG')
        conv_base64 = base64.b64encode(conv_buf.getvalue()).decode('utf-8')

        return render_template_string(
            HTML,
            original=original_data,
            converted=conv_base64,
            pixel_size=pixel_size,
            color_count=color_count,
            width=small_w,
            height=small_h
        )

    return index()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
