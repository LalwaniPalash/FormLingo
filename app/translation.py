from deep_translator import GoogleTranslator

def translate_text(text, dest):
    try:
        return GoogleTranslator(source='auto', target=dest).translate(text)
    except Exception as e:
        print(f"Translation Error: {e}")
        return text

def translate_ans(ans, source, dest='en'):
    try:
        return GoogleTranslator(source=source, target=dest).translate(ans)
    except Exception as e:
        print(f"Translation Error: {e}")
        return ans  # Return original answer if translation fails