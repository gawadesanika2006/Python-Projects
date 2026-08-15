import re


def analyze_file_for_leaks(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        patterns = {
            "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Phone Number": r"\b\d{10}\b",
            "Password Keyword": r"(?i)\b(password|passwd|pass|pwd)\s*[:=]\s*\S+",
            "Confidential Keyword": r"(?i)\b(confidential|secret|private|api_key)\b",
        }

        found_risks = {}
        total_risks_count = 0

        for risk_type, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                found_risks[risk_type] = matches
                total_risks_count += len(matches)

        print("\n================ ANALYSIS REPORT ================")
        if total_risks_count > 0:
            print("⚠️ WARNING: Potential Data Leak Risk Detected!")
            print(f"Total Risks Identified: {total_risks_count}\n")
            print("Detailed Findings:")
            for risk_type, matches in found_risks.items():
                print(f" ❌ {risk_type} Found ({len(matches)}): {matches}")
        else:
            print("✅ Status: Safe! No Data Leak Risk Found.")
        print("=================================================\n")

    except FileNotFoundError:
        print(f"❌ Error: The file '{file_path}' was not found.")
        print("Please check the path and try again.")
    except Exception as e:
        print(f"❌ An error occurred: {e}")


file_to_check = input("Enter the path of the text file to analyze: ")
analyze_file_for_leaks(file_to_check)