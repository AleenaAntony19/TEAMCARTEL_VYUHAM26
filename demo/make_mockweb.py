from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageEnhance

from shield import pdq

BASE = Path(__file__).resolve().parent
OUT = BASE / "mockweb"


def _victim() -> Image.Image:
    path = BASE / "faces/victim_1.jpg"
    if path.exists():
        return Image.open(path).convert("RGB")
    img = Image.new("RGB", (300, 300), (220, 200, 180))
    d = ImageDraw.Draw(img)
    d.ellipse((90, 60, 210, 190), fill=(220, 180, 150))
    d.ellipse((120, 110, 135, 125), fill=(20, 20, 20))
    d.ellipse((165, 110, 180, 125), fill=(20, 20, 20))
    d.arc((130, 140, 170, 170), 0, 180, fill=(120, 40, 40), width=4)
    d.rectangle((80, 200, 220, 300), fill=(40, 70, 120))
    return img


def _overlay(img: Image.Image) -> Image.Image:
    out = img.copy()
    d = ImageDraw.Draw(out)
    d.text((10, 10), "LEAKED", fill=(255, 0, 0))
    return out


def _screenshot(img: Image.Image) -> Image.Image:
    canvas = Image.new("RGB", (img.width + 80, img.height + 80), (30, 30, 30))
    canvas.paste(img, (40, 40))
    return canvas


def _face_on_body(victim: Image.Image, decoy: Image.Image) -> Image.Image:
    out = decoy.copy()
    try:
        arr = cv2.cvtColor(np.array(victim), cv2.COLOR_RGB2BGR)
        from shield.face import detect_faces
        faces = detect_faces(arr)
        if len(faces):
            x, y, w, h = map(int, faces[0][:4])
            face_img = victim.crop((x, y, x + w, y + h)).resize((90, 90))
            out.paste(face_img, (out.width // 2 - 45, 40))
    except Exception:
        # paste center crop of victim as fallback
        center = victim.crop((75, 50, 225, 200)).resize((90, 90))
        out.paste(center, (out.width // 2 - 45, 40))
    return out


def _make_decoy(i: int) -> Image.Image:
    img = Image.new("RGB", (300, 300), (180 + i % 40, 160 + i % 30, 140 + i % 20))
    d = ImageDraw.Draw(img)
    d.ellipse((90, 60, 210, 190), fill=(200, 160 + i % 40, 130))
    d.ellipse((120, 110, 135, 125), fill=(20, 20, 20))
    d.ellipse((165, 110, 180, 125), fill=(20, 20, 20))
    return img


def build(out: str | Path = OUT):
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    (out / "img").mkdir(parents=True)
    (out / "forum").mkdir()
    (out / "gallery").mkdir()
    (out / "directory").mkdir()
    (out / "paste").mkdir()
    (out / "blog").mkdir()
    (out / "private").mkdir()

    victim = _victim()

    transforms = {
        "orig.jpg": victim,
        "q30.jpg": victim,
        "resize50.jpg": victim.resize((victim.width // 2, victim.height // 2)),
        "crop5.jpg": victim.crop((int(victim.width * 0.05), int(victim.height * 0.05), victim.width, victim.height)),
        "flip.jpg": victim.transpose(Image.FLIP_LEFT_RIGHT),
        "rot90.jpg": victim.transpose(Image.ROTATE_90),
        "overlay.jpg": _overlay(victim),
        "bright.jpg": ImageEnhance.Brightness(victim).enhance(1.2),
        "screenshot.jpg": _screenshot(victim),
        "crop30.jpg": victim.crop((int(victim.width * 0.3), int(victim.height * 0.3), victim.width, victim.height)),
    }
    for name, img in transforms.items():
        q = 30 if name == "q30.jpg" else 90
        img.save(out / "img" / name, "JPEG", quality=q)

    decoys = []
    for i in range(40):
        img = _make_decoy(i)
        img.save(out / "img" / f"decoy_{i:02d}.jpg", "JPEG", quality=90)
        decoys.append(img)

    _face_on_body(victim, decoys[0]).save(out / "img" / "face_on_body.jpg", "JPEG", quality=90)

    # forum: 3 threads x 4 pages
    for t in range(3):
        for p in range(1, 5):
            imgs = ["orig.jpg", "q30.jpg", "flip.jpg"][t % 3]
            next_link = (
                f'<a rel="next" href="thread{t+1}_page{p+1}.html">Next &raquo;</a>'
                if p < 4 else ""
            )
            html = (
                f"<html><body><div class='thread'><h1>Thread {t+1} page {p}</h1>"
                f"<img src='../img/{imgs}'><img src='../img/decoy_{t:02d}.jpg'>"
                f"{next_link}</div></body></html>"
            )
            (out / "forum" / f"thread{t+1}_page{p}.html").write_text(html)
    (out / "forum" / "index.html").write_text(
        "<html><body><div class='thread'>"
        "<a href='thread1_page1.html'>T1</a> <a href='thread2_page1.html'>T2</a> "
        "<a href='thread3_page1.html'>T3</a></div></body></html>"
    )

    # gallery: 60 lazy images
    cards = "".join(
        f"<div class='gallery'><img data-src='../img/{'orig.jpg' if i == 0 else f'decoy_{i%40:02d}.jpg'}'></div>"
        for i in range(60)
    )
    (out / "gallery" / "index.html").write_text(
        f"<html><body><div class='gallery'>{cards}</div>"
        "<script>let i=0;setInterval(()=>{{if(i<60){{let im=document.createElement('img');"
        "im.dataset.src='../img/decoy_'+((i++)%40).toString().padStart(2,'0')+'.jpg';"
        "document.querySelector('.gallery').appendChild(im);}}}}),50);</script></body></html>"
    )

    # directory: 20 cards
    cards = "".join(
        f"<div class='card'><img src='../img/decoy_{i%40:02d}.jpg'><p>Name {i}</p></div>"
        for i in range(20)
    )
    (out / "directory" / "index.html").write_text(f"<html><body>{cards}</body></html>")

    # paste
    (out / "paste" / "index.html").write_text(
        "<html><body><pre>Acme Corp dump\nAadhaar 2345 6789 0120 (invalid checksum)\n</pre></body></html>"
    )
    (out / "blog" / "index.html").write_text(
        "<html><body><img src='../img/rot90.jpg'><p>Acme Corp</p></body></html>"
    )
    (out / "private" / "index.html").write_text("<html><body>private</body></html>")
    (out / "robots.txt").write_text("User-agent: *\nDisallow: /private/\n")

    # leak bank
    bank = pdq.HashBank()
    victim_rgb = np.array(victim)
    bank.add_reference("victim", "victim", victim_rgb)
    bank_path = BASE / "leak_bank.json"
    bank.save(bank_path)

    bank_json = json.loads(bank_path.read_text())
    bank_json["text_hits"] = [
        {"url": "http://127.0.0.1:8765/paste/", "title": "Acme Corp dump", "snippet": "Aadhaar dump", "tier": 1},
        {"url": "http://127.0.0.1:8765/blog/", "title": "Acme blog", "snippet": "leak", "tier": 2},
    ]
    bank_path.write_text(json.dumps(bank_json, indent=2))
    return out


if __name__ == "__main__":
    print(build())

