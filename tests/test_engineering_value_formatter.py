from services.engineering_value_formatter import EngineeringValueFormatter


def test_known_values_receive_source_faithful_english_labels() -> None:
    formatter = EngineeringValueFormatter()
    assert formatter.format_value("kein_Stecker_erkannt") == "kein_Stecker_erkannt (no connector detected)"
    assert formatter.format_value("Stby_Ladevorbed_nicht_erfuellt") == "Stby_Ladevorbed_nicht_erfuellt (standby, charging prerequisites not fulfilled)"
    assert formatter.format_value("Fehler") == "Fehler (fault)"


def test_text_translation_is_idempotent_and_preserves_unknown_values() -> None:
    formatter = EngineeringValueFormatter()
    source = "HVLM_CP_State_A = A\nHVLM_Steckerstatus_A = kein_Stecker_erkannt\n"
    once = formatter.format_text(source)
    twice = formatter.format_text(once)
    assert once == twice
    assert "A\n" in once
    assert "kein_Stecker_erkannt (no connector detected)" in once


def test_formatter_handles_known_values_in_any_trace_report_text() -> None:
    formatter = EngineeringValueFormatter()
    text = "BLF: Fehler\nDLT: kein_Fehler\nPCAP: nicht_bekannt\nMF4: kein_Zustand_erkannt"
    rendered = formatter.format_text(text)
    assert "Fehler (fault)" in rendered
    assert "kein_Fehler (no fault)" in rendered
    assert "nicht_bekannt (unknown)" in rendered
    assert "kein_Zustand_erkannt (no state detected)" in rendered
