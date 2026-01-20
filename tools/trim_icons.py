from PIL import Image
import os


def trim_bbox(img):
    if img.mode in ('RGBA', 'LA') or ('transparency' in img.info):
        alpha = img.split()[-1]
        bbox = alpha.getbbox()
        if bbox:
            return bbox
    rgb = img.convert('RGB')
    w, h = rgb.size
    pixels = rgb.load()
    minx, miny, maxx, maxy = w, h, -1, -1
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            if r < 250 or g < 250 or b < 250:
                if x < minx:
                    minx = x
                if y < miny:
                    miny = y
                if x > maxx:
                    maxx = x
                if y > maxy:
                    maxy = y
    if maxx >= minx and maxy >= miny:
        return (minx, miny, maxx + 1, maxy + 1)
    return (0, 0, w, h)


def make_full_bleed(src, dst):
    img = Image.open(src).convert('RGBA')
    bbox = trim_bbox(img)
    cropped = img.crop(bbox)
    target = 1024
    w, h = cropped.size
    scale = target / max(w, h)
    new_size = (max(1, int(w * scale)), max(1, int(h * scale)))
    resized = cropped.resize(new_size, Image.LANCZOS)
    canvas = Image.new('RGBA', (target, target), (255, 255, 255, 0))
    x = (target - new_size[0]) // 2
    y = (target - new_size[1]) // 2
    canvas.paste(resized, (x, y), resized)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    canvas.save(dst)
    print('Saved', dst)


base = r"c:\Users\PC\Desktop\FULLPOS_PROYECTO"
fullpos_src = os.path.join(base, "FULLPOS", "assets", "imagen", "FULLPOS_icon_1024x1024.png")
fullpos_dst = os.path.join(base, "FULLPOS", "assets", "imagen", "FULLPOS_icon_1024x1024_full.png")
owner_src = os.path.join(base, "FULLPOS_OWNER", "assets", "logo", "FULLPOS_OWNER_icon_1024x1024.png")
owner_dst = os.path.join(base, "FULLPOS_OWNER", "assets", "logo", "FULLPOS_OWNER_icon_1024x1024_full.png")

make_full_bleed(fullpos_src, fullpos_dst)
make_full_bleed(owner_src, owner_dst)
