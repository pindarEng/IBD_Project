import time
import logging
import re, string
import pandas as pd
from urllib.parse import urlparse
from collections import Counter
import math
import whois

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# higher risk words
RISK_KEYWORDS = ["bank", "payment", "wire", "transfer", "paypal", "secure", "login"]
# some short forms
# SHORTENERS = ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "buff.ly"]


def get_url_length(url): 
    return len(url)

def count_letters(url): 
    return sum(char.isalpha() for char in url)

def count_digits(url): 
    return sum(char.isdigit() for char in url)

def count_special_chars(url): 
    return sum(char in string.punctuation for char in url)

def has_ip(url): 
    return int(bool(re.search(r'\d{1,3}(?:\.\d{1,3}){3}', url)))

def has_risk_keywords(url): 
    return sum(word in url.lower() for word in RISK_KEYWORDS)

def contains_https(url): 
    return int(urlparse(url).scheme == 'https')

def calculate_shannon_entropy(text):
    """
    Calculate Shannon Entropy to measure randomness in domain/URL.
    Higher entropy suggests algorithmically generated domains.
    """
    if not text:
        return 0.0
    
    # Count character frequency
    counter = Counter(text)
    length = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def count_subdomains(url):
    """
    Count the number of subdomains in the URL.
    More subdomains can indicate suspicious URLs.
    """
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        hostname = parsed.netloc
        # Remove port if present
        hostname = hostname.split(':')[0]
        # Count dots (subdomain separators)
        parts = hostname.split('.')
        # Subtract 2 for domain and TLD (e.g., example.com)
        subdomain_count = max(0, len(parts) - 2)
        return subdomain_count
    except:
        return 0

def extract_ngrams(text, n=3):
    """
    Extract character n-grams from text.
    Returns a list of n-grams.
    """
    if len(text) < n:
        return [text]
    return [text[i:i+n] for i in range(len(text) - n + 1)]

def count_suspicious_chars(url):
    """
    Count suspicious characters like @, -, _, etc.
    """
    suspicious = ['@', '-', '_', '//']
    count = sum(url.count(char) for char in suspicious)
    return count

def count_dots(url):
    """Count number of dots in URL"""
    return url.count('.')

def count_hyphens(url):
    """Count number of hyphens in URL"""
    return url.count('-')

def count_underscores(url):
    """Count number of underscores in URL"""
    return url.count('_')

def count_slashes(url):
    """Count number of slashes in URL"""
    return url.count('/')

def count_question_marks(url):
    """Count number of question marks in URL"""
    return url.count('?')

def count_equal_signs(url):
    """Count number of equal signs in URL"""
    return url.count('=')

def count_at_symbols(url):
    """Count number of @ symbols in URL"""
    return url.count('@')

def count_ampersands(url):
    """Count number of ampersands in URL"""
    return url.count('&')

def get_path_length(url):
    """Get the length of the URL path"""
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        return len(parsed.path)
    except:
        return 0

def has_suspicious_tld(url):
    """
    Check if URL has a suspicious top-level domain.
    Common suspicious TLDs include .tk, .ml, .ga, .cf, .gq
    """
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
    return int(any(url.lower().endswith(tld) for tld in suspicious_tlds))

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
    """
    Perform comprehensive lexical and statistical analysis on URL.
    Extracts features mentioned in the paper for malicious URL detection.
    """
    logger.debug(f"Performing lexical analysis for {url}")
    df = pd.DataFrame([{'url': url}])
    return perform_lexical_analysis_on_df(df)

def perform_lexical_analysis_on_df(df_input: pd.DataFrame) -> pd.DataFrame:
    """
    Batch processing for lexical analysis.
    """
    df = df_input.copy()
    
    # Store original URL with scheme
    original_url = df['url'].copy()
    df['has_https'] = df['url'].apply(contains_https)

    # Clean URL for analysis
    df['url'] = (df['url']
                 .str.replace("http://", "", regex=False)
                 .str.replace("https://", "", regex=False)
                 .str.replace("www.", "", regex=False)
    )
    
    # Basic lexical features
    df['url_len'] = df['url'].apply(get_url_length)
    df['letters_count'] = df['url'].apply(count_letters)
    df['digits_count'] = df['url'].apply(count_digits)
    df['special_chars_count'] = df['url'].apply(count_special_chars)
    
    # Specific character counts (as mentioned in paper)
    df['dot_count'] = df['url'].apply(count_dots)
    df['hyphen_count'] = df['url'].apply(count_hyphens)
    df['underscore_count'] = df['url'].apply(count_underscores)
    df['slash_count'] = df['url'].apply(count_slashes)
    df['question_mark_count'] = df['url'].apply(count_question_marks)
    df['equal_sign_count'] = df['url'].apply(count_equal_signs)
    df['at_symbol_count'] = df['url'].apply(count_at_symbols)
    df['ampersand_count'] = df['url'].apply(count_ampersands)
    
    # Structural features
    df['has_ip'] = df['url'].apply(has_ip)
    df['subdomain_count'] = df['url'].apply(count_subdomains)
    df['path_length'] = df['url'].apply(get_path_length)
    df['suspicious_tld'] = df['url'].apply(has_suspicious_tld)
    
    # Statistical features (Shannon Entropy for randomness detection)
    df['url_entropy'] = df['url'].apply(calculate_shannon_entropy)
    
    # Extract domain for entropy calculation
    def get_domain(url_str):
        try:
            parsed = urlparse(url_str if url_str.startswith('http') else 'http://' + url_str)
            return parsed.netloc.split(':')[0]
        except:
            return url_str
    
    df['domain'] = df['url'].apply(get_domain)
    df['domain_entropy'] = df['domain'].apply(calculate_shannon_entropy)
    
    # Semantic/Content features
    df['has_risk_words'] = df['url'].apply(has_risk_keywords)
    df['suspicious_char_count'] = df['url'].apply(count_suspicious_chars)
    
    # Ratios (normalized features)
    df['digit_ratio'] = df['digits_count'] / (df['url_len'] + 1)  # +1 to avoid division by zero
    df['letter_ratio'] = df['letters_count'] / (df['url_len'] + 1)
    df['special_char_ratio'] = df['special_chars_count'] / (df['url_len'] + 1)

    logger.debug(f"Extracted {len(df.columns)} lexical features")
    
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
