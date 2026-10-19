import io

from PIL import Image, ImageDraw

from opti.sandbox.visual import image_candidates


def test_only_visible_small_images_are_hashed_from_existing_screenshot() -> None:
    screen = Image.new("RGB", (300, 160), "white")
    draw = ImageDraw.Draw(screen)
    draw.rectangle((25, 25, 52, 92), fill="black")
    draw.polygon(((57, 90), (85, 55), (57, 30)), fill="black")
    stream = io.BytesIO()
    screen.save(stream, format="PNG")
    candidates = image_candidates(
        stream.getvalue(),
        [
            {"x": 20, "y": 20, "width": 70, "height": 80},
            {"x": -100, "y": 20, "width": 70, "height": 80},
            {"x": 10, "y": 10, "width": 700, "height": 60},
            {"x": 10, "y": 10, "width": True, "height": 50},
            {"x": 100, "y": 30, "width": 40, "height": 40},
        ],
    )
    assert len(candidates) == 1
    assert candidates[0]["box"] == {"x": 20, "y": 20, "width": 70, "height": 80}
    assert len(candidates[0]["dhash64"]) == 16
