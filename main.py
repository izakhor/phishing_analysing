import json
from pathlib import Path
import eml_parser
import report
import risk


def ask_eml_file_path():
    while True:
        user_input = input("Chemin complet du fichier .eml a analyser : ").strip().strip('"')

        if not user_input:
            print("Le chemin du fichier est obligatoire.")
            continue

        eml_path = Path(user_input)

        if eml_path.suffix.lower() != ".eml":
            print("Le fichier doit avoir l'extension .eml")
            continue

        if not eml_path.is_file():
            print(f"Fichier introuvable : {eml_path}")
            continue

        return str(eml_path)


def main():
    eml_file_path = ask_eml_file_path()

    try:
        analysis_results = eml_parser.parse_email(eml_file_path)

        scores = {
            "headers": risk.calculate_header_score(analysis_results.get("headers", {})),
            "content": risk.calculate_content_score(analysis_results.get("content", {})),
            "attachment": risk.calculate_attachment_score(analysis_results.get("attachments", [])),
        }

        analysis_results["risk_score"] = risk.total_score(scores)
        json_report = report.generate_json_report(analysis_results)

        output_path = Path("phishing_report.json")
        with output_path.open("w", encoding="utf-8") as file:
            json.dump(json_report, file, indent=4, ensure_ascii=False)

        print(f"Rapport genere : {output_path}")

    except Exception as exc:
        print(f"Erreur pendant l'analyse : {exc}")


if __name__ == "__main__":
    main()
