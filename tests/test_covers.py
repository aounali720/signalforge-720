from io import BytesIO
from PIL import Image
from signalforge.covers import render_cover


def test_720_brand_card_is_unique_per_headline_but_reproducible():
    one = render_cover("Illustrative CVE analysis", label="Grid pulse", demo=True)
    assert one == render_cover("Illustrative CVE analysis", label="Grid pulse", demo=True)
    assert one != render_cover("Different case headline", label="Grid pulse", demo=True)
    assert one != render_cover("Illustrative CVE analysis", label="Orbit rings", demo=True)
    image = Image.open(BytesIO(one))
    assert image.size == (1200, 627)
    assert image.format == "PNG"
