from PIL import Image
from pathlib import Path


def make_clean(src, dest, size=1024, padding=0.08, tol=20):
    img = Image.open(src).convert("RGBA")
    w, h = img.size
    corners = [
        img.getpixel((0, 0)),
        img.getpixel((w - 1, 0)),
        img.getpixel((0, h - 1)),
        img.getpixel((w - 1, h - 1)),
    ]
    bg = tuple(sum(c[i] for c in corners) // len(corners) for i in range(3))

    pixels = img.load()
    for y in range(h):
        for x in range(w):
            r, g, b, a = pixels[x, y]
            if (
                abs(r - bg[0]) <= tol
                and abs(g - bg[1]) <= tol
                and abs(b - bg[2]) <= tol
            ):
                pixels[x, y] = (r, g, b, 0)

    bbox = img.getbbox()
    if bbox:
        img = img.crop(bbox)

    target = int(size * (1 - padding * 2))
    img = img.resize((target, target), Image.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    offset = ((size - target) // 2, (size - target) // 2)
    canvas.paste(img, offset, img)
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    canvas.save(dest)


make_clean(
    r"c:\Users\PC\Desktop\FULLPOS_PROYECTO\FULLPOS\assets\imagen\FULLPOS_icon_1024x1024_full.png",
    r"c:\Users\PC\Desktop\FULLPOS_PROYECTO\FULLPOS\assets\imagen\FULLPOS_icon_1024x1024_clean.png",
)
make_clean(
    r"c:\Users\PC\Desktop\FULLPOS_PROYECTO\FULLPOS_OWNER\assets\logo\FULLPOS_OWNER_icon_1024x1024_full.png",
    r"c:\Users\PC\Desktop\FULLPOS_PROYECTO\FULLPOS_OWNER\assets\logo\FULLPOS_OWNER_icon_1024x1024_clean.png",
)

Image.new("RGBA", (1024, 1024), (0, 0, 0, 0)).save(
    r"c:\Users\PC\Desktop\FULLPOS_PROYECTO\FULLPOS\assets\imagen\transparent_1024.png"
)
Image.new("RGBA", (1024, 1024), (0, 0, 0, 0)).save(
    r"c:\Users\PC\Desktop\FULLPOS_PROYECTO\FULLPOS_OWNER\assets\logo\transparent_1024.png"
)

print("done")
