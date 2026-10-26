"""Offline interaction checks: no live feeds or paid APIs are used."""
from pathlib import Path
from streamlit.testing.v1 import AppTest


def test_dashboard_demo_triage_and_draft_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setenv('SF720_DB_PATH', str(tmp_path / 'ui.sqlite'))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py'), default_timeout=30).run()
    assert not app.exception
    app.sidebar.button[1].click().run()
    assert not app.exception
    assert any('4 synthetic' in warning.value for warning in app.warning)
    assert len(app.tabs) == 8
    # Inspect demo cases and save a journal entry; evidence must refresh immediately.
    next(s for s in app.selectbox if s.label == 'Dataset').select('Demo').run()
    next(s for s in app.selectbox if s.label == 'Case state').select('Investigating')
    next(t for t in app.text_area if t.label == 'Analyst observations / next steps').input('Verify declared lab assets')
    next(b for b in app.button if b.label == 'Save triage decision').click().run()
    assert not app.exception
    assert any('Queue and evidence updated' in s.value for s in app.success)
    from signalforge.database import list_threats
    assert any(r.status == 'Investigating' and r.analyst_notes == 'Verify declared lab assets'
               for r in list_threats())
    next(c for c in app.checkbox if c.label == 'Show synthetic scenarios in Content Studio').check().run()
    next(b for b in app.button if b.label == 'Generate source-grounded LinkedIn draft').click().run()
    assert 'synthetic' in app.session_state['tp_post'].lower()
    app.multiselect[0].set_value([]).run()
    assert not any(t.label == 'Review and edit before publishing' for t in app.text_area)
    assert not app.exception


def test_dashboard_withholds_provider_error_details(tmp_path, monkeypatch):
    import requests
    import signalforge.ai
    monkeypatch.setenv('SF720_DB_PATH', str(tmp_path / 'errors.sqlite'))
    def fail(*args, **kwargs):
        raise requests.HTTPError('PRIVATE_PROVIDER_RESPONSE_SENTINEL')
    monkeypatch.setattr(signalforge.ai, 'ai_linkedin', fail)
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py'), default_timeout=30).run()
    app.sidebar.button[1].click().run()
    next(c for c in app.checkbox if c.label == 'Show synthetic scenarios in Content Studio').check().run()
    next(s for s in app.selectbox if s.label == 'Writing engine').select('OpenAI').run()
    next(b for b in app.button if b.label == 'Generate source-grounded LinkedIn draft').click().run()
    assert not app.exception
    assert any('Draft generation failed' in e.value for e in app.error)
    assert all('PRIVATE_PROVIDER_RESPONSE_SENTINEL' not in e.value for e in app.error)
