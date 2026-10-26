"""Personalized, reproducible 720-series editorial artwork.

Each title produces a distinct but deterministic pattern. No invented photograph
or documentary-looking scene is ever output.
"""
from __future__ import annotations
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import math
import random


def _font(size: int, bold: bool = False):
    names = (["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "C:/Windows/Fonts/arialbd.ttf"] if bold
             else ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "C:/Windows/Fonts/arial.ttf"])
    for name in names:
        if Path(name).exists():
            return ImageFont.truetype(name, size)
    return ImageFont.load_default()


def render_cover(headline: str, *, label: str = "Signal trace", demo: bool = False) -> bytes:
    """Generate a unique 1200 × 627 card, seeded by headline and @aounali720."""
    W, H = 1200, 627
    identity = sha256(("@aounali720|SF720|" + headline).encode("utf-8")).digest()
    rng = random.Random(int.from_bytes(identity[:8], "big"))
    palette = [(22, 176, 215), (101, 214, 175), (121, 134, 255)][identity[8] % 3]
    canvas = Image.new("RGB", (W, H), (8, 16, 32))
    draw = ImageDraw.Draw(canvas)
    # Wide-column gradient stripe backdrop, fast and deterministic.
    for y in range(H):
        t = y / H
        draw.line((0, y, W, y), fill=(int(9+13*t), int(18+16*t), int(32+24*t)), width=1)
    for x in range(40, W, 52):
        draw.line((x, 40, x, H-40), fill=(24, 46, 65), width=1)
    for y in range(34, H, 52):
        draw.line((32, y, W-32, y), fill=(24, 46, 65), width=1)
    motif = label.lower()
    if "orbit" in motif:
        for k in range(9):
            radius = 52 + k*47 + rng.randrange(-8,9)
            draw.ellipse((930-radius, 285-radius, 930+radius, 285+radius),
                         outline=palette if k % 3 == 0 else (35, 65, 86), width=2)
    elif "grid" in motif:
        for j in range(7):
            for i in range(10):
                pos=(795+i*38, 130+j*45)
                size=rng.randrange(4, 15)
                draw.rectangle((*pos, pos[0]+size, pos[1]+size),
                               fill=palette if (i+j) % 4 == 0 else (30, 75, 91))
    else:
        points=[]
        for i in range(48):
            x=710+i*10
            y=290+math.sin(i*.34)*35 + rng.randrange(-32,33)
            points.append((x,int(y)))
        draw.line(points, fill=palette, width=4, joint="curve")
        for p in points[::4]:
            draw.ellipse((p[0]-5,p[1]-5,p[0]+5,p[1]+5),fill=(235,244,247))
    # Identity and asymmetric composition distinguish this from common SOC templates.
    draw.polygon([(42,64),(62,44),(83,64),(62,85)], outline=palette, width=4)
    draw.text((98,46),"SIGNALFORGE", font=_font(35, True),fill=(230,243,251))
    draw.text((462,53),"/ 720",font=_font(29,True),fill=palette)
    draw.text((53,126),label.upper()[:32],font=_font(18,True),fill=palette)
    words=(headline.strip() or "THREAT SIGNALS INTO EVIDENCE")[:150].split()
    lines=[]; current=""
    for word in words:
        trial=(current+" "+word).strip()
        if draw.textbbox((0,0),trial,font=_font(49,True))[2] > 900 and current:
            lines.append(current);current=word
        else: current=trial
    if current:lines.append(current)
    lines=lines[:4]
    for i,line in enumerate(lines):
        draw.text((52,195+i*72),line,font=_font(49,True),fill=(248,251,255),stroke_width=0)
    draw.line((53,546,1140,546), fill=palette, width=2)
    draw.text((54,558),"AOUNSEC // @aounali720",font=_font(17,True),fill=(196,217,235))
    draw.text((540,560),"SOURCE-LINKED  •  HUMAN-REVIEWED",font=_font(15),fill=(155,182,202))
    if demo:
        draw.rectangle((930,570,1152,609),fill=(99,54,22))
        draw.text((945,578),"SYNTHETIC DEMO",font=_font(17,True),fill=(255,215,150))
    else:
        draw.text((1100,579),identity.hex()[:6].upper(),font=_font(12),fill=(122,151,172))
    output=BytesIO();canvas.save(output,format="PNG",optimize=True);return output.getvalue()
