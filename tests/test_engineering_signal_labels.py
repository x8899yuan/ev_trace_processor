from services.engineering_value_formatter import EngineeringValueFormatter


def test_known_signal_names_keep_identifier_and_add_english_label() -> None:
    formatter = EngineeringValueFormatter()
    assert formatter.format_signal_name("KL_Fehler_HV_Heizer") == "KL_Fehler_HV_Heizer (HV heater fault)"
    assert formatter.format_signal_name("HVLM_Steckerstatus_A") == "HVLM_Steckerstatus_A (connector status A)"
    assert formatter.format_signal_name("HVLM_Ladevorgang_Anf") == "HVLM_Ladevorgang_Anf (charging request)"
    assert formatter.format_signal_name("HVLM_ZustandLadeablauf") == "HVLM_ZustandLadeablauf (charging sequence state)"
    assert formatter.format_signal_name("HVLM_CP_State_A") == "HVLM_CP_State_A (control-pilot state A)"


def test_signal_and_value_labels_are_both_applied_in_report_text() -> None:
    formatter = EngineeringValueFormatter()
    source = "Primary fault signal: KL_Fehler_HV_Heizer\nHVLM_Steckerstatus_A = kein_Stecker_erkannt\n"
    rendered = formatter.format_text(source)
    assert "KL_Fehler_HV_Heizer (HV heater fault)" in rendered
    assert "HVLM_Steckerstatus_A (connector status A) = kein_Stecker_erkannt (no connector detected)" in rendered


def test_signal_text_formatting_is_idempotent() -> None:
    formatter = EngineeringValueFormatter()
    once = formatter.format_text("KL_Fehler_HV_Heizer: Fehler")
    assert formatter.format_text(once) == once
