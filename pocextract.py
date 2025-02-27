from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import re

# Import colorama for red text
try:
    from colorama import Fore, init
    init(autoreset=True, convert=True, strip=False)  # Fixes Windows terminal issues
    is_colorama_installed = True
except ImportError:
    is_colorama_installed = False

def is_valid_url(url):
    pattern = re.compile(
        r"^(https?:\/\/)?"  # Optional http or https
        r"([a-zA-Z0-9.-]+)\."  # Domain name
        r"([a-zA-Z]{2,6})"  # Domain extension
        r"(\/[^\s]*)?$"  # Optional path
    )
    return bool(pattern.match(url))

def get_main_url():
    while True:
        url = input("Enter the monthly URL on the format https://msrc.microsoft.com/update-guide/releaseNote/YYYY-MMM : ").strip()
        if is_valid_url(url):
            return url
        print("Invalid URL. Please enter a valid URL on the format https://msrc.microsoft.com/update-guide/releaseNote/YYYY-MMM.")

MAIN_URL = get_main_url()
print(f"Using URL: {MAIN_URL}")

def get_cve_links(driver):
    """Extracts all CVE links from the main page."""
    driver.get(MAIN_URL)
    WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.XPATH, "//a[contains(@href, '/vulnerability/CVE-')]")))

    cve_links = [cve.get_attribute("href") for cve in driver.find_elements(By.XPATH, "//a[contains(@href, '/vulnerability/CVE-')]")]
    
    print(f"[INFO] Found {len(cve_links)} CVE links.")
    return cve_links

def check_exploit_maturity(driver, cve_url):
    """Checks if the CVE has PoC, Functional exploit maturity and if it's weaponized."""
    driver.get(cve_url)
    print(f"[INFO] Checking: {cve_url}")

    try:
        WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(2)

        rows = driver.find_elements(By.XPATH, "//div[@role='gridcell']")

        maturity_value = None
        is_weaponized = False

        # Find Exploit Code Maturity
        for i in range(len(rows)):
            if "Exploit Code Maturity" in rows[i].text:
                maturity_value = rows[i + 1].text.strip()
                break

        # If it's Functional, treat it as Proof-of-Concept
        if maturity_value == "Functional":
            maturity_value = "Proof-of-Concept"

        # Check Exploitability section for Weaponized status
        try:
            exploited_field = driver.find_element(By.XPATH, "//*[@id='exploitability']/div/div[2]/div/dl/dd[2]")
            exploited_value = exploited_field.text.strip().lower()

            if exploited_value == "yes":
                is_weaponized = True

        except Exception:
            pass  # No need to print anything if the exploited field isn't found

        # Decide what to print based on findings
        if maturity_value == "Proof-of-Concept" and is_weaponized:
            match_text = f"[MATCH] {cve_url} - Weaponized"
        elif maturity_value == "Proof-of-Concept":
            match_text = f"[MATCH] {cve_url} - Proof-of-Concept"
        else:
            return None  # No need to print anything if it's not PoC or Weaponized

        # Print match in red
        print(Fore.RED + match_text if is_colorama_installed else match_text)
        return cve_url, "Weaponized" if is_weaponized else "Proof-of-Concept"

    except Exception as e:
        print(f"[ERROR] {cve_url} - Exception occurred: {e}")

    return None

def main():
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    driver = webdriver.Chrome(options=options)

    try:
        cve_links = get_cve_links(driver)
        matching_cves = []

        for cve_url in cve_links:
            result = check_exploit_maturity(driver, cve_url)
            if result:
                matching_cves.append(result)

        print("\n[RESULTS] CVEs with Proof-of-Concept or Weaponized status:")
        for cve, maturity in matching_cves:
            result_text = f"{cve} - {maturity}"
            print(Fore.RED + result_text if is_colorama_installed else result_text)

    finally:
        driver.quit()
    input("Press Enter to exit...")  # Keeps terminal open after execution    

if __name__ == "__main__":
    main()
