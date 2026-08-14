"""
Test that background.js can handle both age-input and birthday-spinbutton variants
of the /about-you page.
"""

from pathlib import Path


def test_about_you_recognizes_both_age_and_birthday_fields():
    """
    Ensure fillAboutYou() and submit_about_you recognize:
      1. Old variant: input[name="age"] or input[type="number"][inputmode="numeric"]
      2. New variant: input[type="hidden"][name="birthday"] + spinbuttons
    """
    bg_js = (Path(__file__).parents[1] / "chrome_plus_ver" / "background.js").read_text(encoding="utf-8")

    # fillAboutYou should check for birthdayHidden
    assert 'const birthdayHidden = firstNode(\'input[type="hidden"][name="birthday"]\')' in bg_js, \
        "fillAboutYou must detect the birthday hidden input"
    assert 'if (!nameInput && !ageInput && !birthdayHidden)' in bg_js, \
        "fillAboutYou must accept either ageInput or birthdayHidden"
    assert 'else if (birthdayHidden && !String(birthdayHidden.value || \'\').trim())' in bg_js, \
        "fillAboutYou must fill birthdayHidden when present"
    assert 'div[role="spinbutton"][contenteditable="true"]' in bg_js, \
        "fillAboutYou must target the spinbutton divs for MM/DD/YYYY"

    # submit_about_you should also check for birthdayHidden
    submit_section = bg_js[bg_js.index("case 'submit_about_you':") : bg_js.index("case 'submit_about_you':") + 5000]
    assert 'const birthdayHidden = firstNode(\'input[type="hidden"][name="birthday"]\')' in submit_section, \
        "submit_about_you must detect birthday hidden input"
    assert 'if (!nameInput && !ageInput && !birthdayHidden)' in submit_section, \
        "submit_about_you must accept either ageInput or birthdayHidden"
    assert 'else if (birthdayHidden)' in submit_section, \
        "submit_about_you must fill birthday when present"


def test_birthday_derivation_from_age():
    """
    The birthday variant derives MM/DD/YYYY from the age param by subtracting
    age years from today. Verify the logic is present.
    """
    bg_js = (Path(__file__).parents[1] / "chrome_plus_ver" / "background.js").read_text(encoding="utf-8")

    # Both fillAboutYou and submit_about_you should derive birthday from age
    assert 'const birthYear = today.getFullYear() - age' in bg_js, \
        "Must derive birthYear by subtracting age from current year"
    assert 'const birthMonth = 1 + Math.floor(Math.random() * 12)' in bg_js, \
        "Must generate a random month 1..12"
    assert 'const birthDay = 1 + Math.floor(Math.random() * 28)' in bg_js, \
        "Must generate a random day 1..28 (safe for all months)"
    assert 'await trustedFill(spinbuttons[0], monthStr)' in bg_js, \
        "Must fill the first spinbutton (month) with monthStr"
    assert 'await trustedFill(spinbuttons[1], dayStr)' in bg_js, \
        "Must fill the second spinbutton (day) with dayStr"
    assert 'await trustedFill(spinbuttons[2], yearStr)' in bg_js, \
        "Must fill the third spinbutton (year) with yearStr"
