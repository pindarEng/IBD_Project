import time
import logging
import re, string
import pandas as pd
from urllib.parse import urlparse
import whois

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# higher risk words
RISK_KEYWORDS = ["bank", "payment", "wire", "transfer", "paypal", "secure", "login"]
# some short forms
# SHORTENERS = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "buff.ly"]


def get_url_length(url): return len(url)
def count_letters(url): return sum(char.isalpha() for char in url)
def count_digits(url): return sum(char.isdigit() for char in url)
def count_special_chars(url): return sum(char in string.punctuation for char in url)
def has_ip(url): return int(bool(re.search(r'\d{1,3}(?:\.\d{1,3}){3}', url)))
def has_risk_keywords(url): return sum(word in url.lower() for word in RISK_KEYWORDS)
def contains_https(url): return int(urlparse(url).scheme == 'https')

# def has_shortening_service(url):
#     pattern = re.compile(r'bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|tr\.im|is\.gd|cli\.gs|j\.mp|bit\.do')
#     return int(bool(pattern.search(url)))


# def is_short_url(url):
#     pattern = re.compile(r'bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|tr\.im|is\.gd|cli\.gs|j\.mp|bit\.do')
#     return int(bool(pattern.search(url)))


# TODO: expand url - somehow
# def expand_url(short_url):
#     """
#     Simulate URL expansion. 
#     In production, this would use requests.head(url, allow_redirects=True).
#     """
#     logger.info(f"Expanding URL: {short_url}")
#     # Mock expansion logic
#     time.sleep(0.5) # Simulate network delay
#     expanded = f"{short_url}/expanded/target-page"
#     logger.info(f"Expanded to: {expanded}")
#     return expanded

def perform_lexical_analysis(url) -> pd.DataFrame:
    logger.info(f" initial lexical analysis for {url} ")
    df = pd.DataFrame([{'url': url}])
    
    df['has_https'] = df['url'].apply(contains_https)

    df['url'] = (df['url']
                 .str.replace("http://", "", regex=False)
                 .str.replace("https://", "", regex=False)
                 .str.replace("www.", "", regex=False)
    )
    df['url_len'] = df['url'].apply(get_url_length)
    df['letters_count'] = df['url'].apply(count_letters)
    df['digits_count'] = df['url'].apply(count_digits)
    df['special_chars_count'] = df['url'].apply(count_special_chars)
    df['has_ip'] = df['url'].apply(has_ip)
    df['has_risk_words'] = df['url'].apply(has_risk_keywords)

    logger.info(f"resulted dataframe for the lexical analysis \n {df}")
    # print(df)
    return df

# url : a b c d features -> input

def perform_deep_analysis(df: pd.DataFrame):
    """
    Path 2: Deep Analysis (WHOIS, DNS, etc.)
    """
    url = df.loc[0,'url']
    print(url)
    domain = urlparse("http://" + url).netloc
    print(domain)
    logger.info(f"--- [SLOW PATH] Starting Deep Analysis for domain: {domain} ---")

    # whois lookup
    logger.info("Performing WHOIS lookup...")
    try:
        whois_data = whois.whois(domain)
        if whois_data.creation_date:
            import datetime
            creation_date = whois_data.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]  # take first if multiple
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            df['domain_age_days'] = (pd.Timestamp.now() - pd.Timestamp(creation_date)).days
        else:
            df['domain_age_days'] = None
    except Exception as e:
        print(f"whois lookup failed: {e}")
        df['domain_age_days'] = None

    logger.info(f"resulted df {df}")
    
    # Simulate DNS lookup
    logger.info("Performing DNS resolution...")
    time.sleep(1)
    
    logger.info(f"--- [SLOW PATH] Deep Analysis Complete for: {url} ---")
