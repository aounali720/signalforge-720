from signalforge.export import safe_cell, safe_csv

def test_export_escapes_formula_cells_from_untrusted_sources():
    assert safe_cell('=HYPERLINK("http://bad", "click")').startswith("'=")
    assert safe_cell("  +42").startswith("'  +")
    assert safe_cell("Normal title") == "Normal title"
    assert safe_csv([{"title": "=1+2", "score": 4}]).splitlines()[1].startswith("'=1+2")
