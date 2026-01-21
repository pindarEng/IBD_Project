#!/usr/bin/env python3
"""
URL Expansion Script
Expands shortened URLs and provides detailed information about redirects.
"""

import sys
import os
import logging
import argparse
import pandas as pd
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helper_functions.url_expander import (
    expand_url,
    expand_url_if_shortened,
    expand_url_aggressive,
    expand_url_comprehensive,
    expand_url_full_coverage,
    has_shortening_service,
    SHORTENERS,
    SELENIUM_AVAILABLE,
    expand_url_with_browser
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def expand_single_url(url, timeout=5, verbose=False, use_browser=False, aggressive=False, full_coverage=False, comprehensive=False):
    """
    Expand a single URL and display results.
    
    Args:
        url: URL to expand
        timeout: Request timeout in seconds
        verbose: Show detailed information
        use_browser: Use browser automation for JavaScript redirects
        aggressive: Attempt expansion on ALL URLs, not just known shorteners
        full_coverage: Maximum coverage (browser first, or browser+HTTP fallback)
        comprehensive: Smart method selection (HTTP first, browser fallback)
    """
    print(f"\n{'='*70}")
    print(f"Original URL: {url}")
    print(f"{'='*70}")
    
    if full_coverage:
        # Full coverage - browser+HTTP combo or browser only
        result = expand_url_full_coverage(url, timeout=timeout, fallback_http=True)
        print(f"Expansion Mode: FULL COVERAGE (Smart method selection)")
        print(f"Strategy: HTTP first → Browser fallback")
        
        print(f"\nExpansion Result:")
        print(f"  - Method Used: {result['method_used'].upper()}")
        print(f"  - Success: {result['expansion_success']}")
        print(f"  - Redirects: {result['redirect_count']}")
        print(f"  - Final URL: {result['expanded_url']}")
        
        if result['was_expanded']:
            print(f"\n✓ URL was expanded!")
        else:
            print(f"\n○ No redirects found")
    elif comprehensive:
        # Comprehensive - smart method selection
        result = expand_url_comprehensive(url, timeout=timeout, prefer_browser=False)
        print(f"Expansion Mode: COMPREHENSIVE (Smart method selection)")
        print(f"Strategy: HTTP first → Browser fallback")
        
        print(f"\nExpansion Result:")
        print(f"  - Method Used: {result['method_used'].upper()}")
        print(f"  - Success: {result['expansion_success']}")
        print(f"  - Redirects: {result['redirect_count']}")
        print(f"  - Final URL: {result['expanded_url']}")
        
        if result['was_expanded']:
            print(f"\n✓ URL was expanded!")
        else:
            print(f"\n○ No redirects found")
    elif aggressive:
        # Aggressive expansion - try on all URLs
        result = expand_url_aggressive(url, timeout=timeout, use_browser=use_browser)
        print(f"Expansion Mode: AGGRESSIVE (all URLs)")
        print(f"Method: {result['method'].upper()}")
        
        print(f"\nExpansion Result:")
        print(f"  - Success: {result['expansion_success']}")
        print(f"  - Redirects: {result['redirect_count']}")
        print(f"  - Final URL: {result['expanded_url']}")
        
        if result['was_expanded']:
            print(f"\n✓ URL was expanded!")
        else:
            print(f"\n○ No redirects found (not shortened)")
    else:
        # Check if it's a known shortened URL
        is_shortened = has_shortening_service(url)
        print(f"Known Shortener: {'Yes' if is_shortened else 'No'}")
        
        if is_shortened:
            # Expand the URL
            result = expand_url_if_shortened(url, timeout=timeout, use_browser=use_browser)
            
            print(f"\nExpansion Result:")
            print(f"  - Method: {result['method'].upper()}")
            print(f"  - Success: {result['expansion_success']}")
            print(f"  - Redirects: {result['redirect_count']}")
            print(f"  - Final URL: {result['expanded_url']}")
            
            if result['expanded_url'] != url:
                print(f"\n✓ URL successfully expanded!")
            elif not result['expansion_success']:
                print(f"\n✗ URL expansion failed")
                if not use_browser and SELENIUM_AVAILABLE:
                    print(f"  💡 Tip: Try using --browser flag for JavaScript-protected URLs")
                elif not use_browser:
                    print(f"  💡 Tip: Install Selenium for browser-based expansion:")
                    print(f"     pip install selenium")
                print(f"  Note: Some shorteners use bot protection (Cloudflare, etc.)")
            else:
                print(f"\n✗ No redirects found")
        else:
            print(f"\nNot a known shortened URL")
            if not aggressive:
                print(f"💡 Tips:")
                print(f"  - Use --aggressive flag to attempt expansion on all URLs")
                print(f"  - Use --comprehensive for smart method selection (recommended)")
                print(f"  - Use --full-coverage for maximum reliability")
    
    if verbose:
        print(f"\n{'='*70}")
        print("Known URL Shorteners:")
        for i, shortener in enumerate(SHORTENERS, 1):
            print(f"  {i:2d}. {shortener}")
        print(f"\nBrowser automation: {'Available ✓' if SELENIUM_AVAILABLE else 'Not installed ✗'}")
    
    print(f"{'='*70}\n")


def expand_from_file(input_file, output_file=None, timeout=5, use_browser=False, aggressive=False):
    """
    Expand URLs from a CSV file.
    
    Args:
        input_file: Path to input CSV file with 'url' column
        output_file: Path to output CSV file (optional)
        timeout: Request timeout in seconds
        use_browser: Use browser automation for JavaScript redirects
        aggressive: Attempt expansion on ALL URLs, not just known shorteners
    """
    logger.info(f"Reading URLs from {input_file}")
    
    try:
        df = pd.read_csv(input_file)
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        return
    
    if 'url' not in df.columns:
        logger.error("Input file must have a 'url' column")
        return
    
    logger.info(f"Processing {len(df)} URLs...")
    if aggressive:
        logger.info("Using AGGRESSIVE expansion mode (all URLs)...")
    elif use_browser:
        logger.info("Using browser automation mode...")
    
    # Add expansion columns
    if aggressive:
        # Aggressive mode - don't check shortener
        df['is_shortened'] = 0
    else:
        # Standard mode - only flag known shorteners
        df['is_shortened'] = df['url'].apply(has_shortening_service)
    
    # Expand URLs
    expansion_results = []
    for idx, row in df.iterrows():
        url = row['url']
        if aggressive:
            result = expand_url_aggressive(url, timeout=timeout, use_browser=use_browser)
        else:
            result = expand_url_if_shortened(url, timeout=timeout, use_browser=use_browser)
        expansion_results.append(result)
        
        if (idx + 1) % 100 == 0:
            logger.info(f"Processed {idx + 1}/{len(df)} URLs")
    
    # Add results to dataframe
    df['expanded_url'] = [r['expanded_url'] for r in expansion_results]
    df['redirect_count'] = [r['redirect_count'] for r in expansion_results]
    df['expansion_success'] = [r['expansion_success'] for r in expansion_results]
    
    # Statistics
    total_urls = len(df)
    shortened_count = df['is_shortened'].sum() if 'is_shortened' in df.columns else 0
    expanded_count = (df['expanded_url'] != df['url']).sum()
    
    print(f"\n{'='*70}")
    print("Expansion Statistics:")
    print(f"  - Total URLs: {total_urls}")
    if not aggressive:
        print(f"  - Known Shortened URLs: {shortened_count} ({shortened_count/total_urls*100:.1f}%)")
    print(f"  - URLs with Redirects: {expanded_count} ({expanded_count/total_urls*100:.1f}%)")
    print(f"{'='*70}\n")
    
    # Save results
    if output_file:
        logger.info(f"Saving results to {output_file}")
        df.to_csv(output_file, index=False)
        logger.info("Done!")
    else:
        # Display sample results
        print("\nSample Results (first 10 rows):")
        print(df[['url', 'is_shortened', 'expanded_url', 'redirect_count']].head(10))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Expand shortened URLs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Expand known shorteners only (fastest)
  python url_expander.py -u "https://bit.ly/3xYz123"
  
  # Comprehensive mode: smart method selection (recommended)
  python url_expander.py -u "https://shorturl.at/kgZHT" --comprehensive
  
  # Full coverage mode: maximum reliability (slower but most reliable)
  python url_expander.py -u "https://shorturl.at/kgZHT" --full-coverage
  
  # Aggressive mode: try to expand ALL URLs (catches unknown shorteners)
  python url_expander.py -u "https://example.com/path" --aggressive
  
  # Browser mode for JavaScript-protected URLs
  python url_expander.py -u "https://shorturl.at/kgZHT" --browser
  
  # Batch with comprehensive mode
  python url_expander.py -f input.csv -o output.csv --comprehensive
  
  # Batch with aggressive expansion
  python url_expander.py -f input.csv -o output.csv --aggressive
        """
    )
    
    parser.add_argument('-u', '--url', type=str, 
                       help='Single URL to expand')
    parser.add_argument('-f', '--file', type=str,
                       help='Input CSV file with URLs')
    parser.add_argument('-o', '--output', type=str,
                       help='Output CSV file for results')
    parser.add_argument('-t', '--timeout', type=int, default=5,
                       help='Request timeout in seconds (default: 5)')
    parser.add_argument('-a', '--aggressive', action='store_true',
                       help='Aggressive mode: attempt expansion on ALL URLs, not just known shorteners')
    parser.add_argument('-b', '--browser', action='store_true',
                       help='Use browser automation (Selenium) for JavaScript redirects')
    parser.add_argument('-c', '--comprehensive', action='store_true',
                       help='Comprehensive mode: smart method selection (HTTP first, browser fallback)')
    parser.add_argument('--full-coverage', action='store_true',
                       help='Full coverage mode: maximum reliability (browser primary)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed information')
    
    args = parser.parse_args()
    
    # Check browser mode prerequisites
    if (args.browser or args.full_coverage) and not SELENIUM_AVAILABLE:
        print("⚠️  Browser mode requires Selenium. Install with:")
        print("   pip install selenium")
        print("\nYou also need Chrome/Chromium installed.")
        return
    
    # Handle different modes
    if args.url:
        expand_single_url(args.url, timeout=args.timeout, verbose=args.verbose, 
                         use_browser=args.browser, aggressive=args.aggressive, 
                         full_coverage=args.full_coverage, comprehensive=args.comprehensive)
    elif args.file:
        expand_from_file(args.file, args.output, timeout=args.timeout, 
                        use_browser=args.browser, aggressive=args.aggressive)
    else:
        # Interactive mode
        print("\n" + "="*70)
        print("URL Expansion Tool")
        print("="*70)
        print(f"Expansion Mode: ", end="")
        if args.full_coverage:
            print("Full Coverage ✓")
        elif args.comprehensive:
            print("Comprehensive ✓")
        elif args.aggressive:
            print("Aggressive ✓")
        else:
            print("Standard (known shorteners only)")
        print(f"Browser: {'Enabled ✓' if args.browser else 'Disabled ✗'}")
        print(f"Selenium: {'Available ✓' if SELENIUM_AVAILABLE else 'Not installed ✗'}")
        print("\nKnown URL Shorteners:")
        for i, shortener in enumerate(SHORTENERS[:10], 1):
            print(f"  {i:2d}. {shortener}")
        if len(SHORTENERS) > 10:
            print(f"  ... and {len(SHORTENERS) - 10} more")
        
        print("\nEnter a URL to expand (or 'quit' to exit):")
        
        while True:
            try:
                url = input("\nURL: ").strip()
                if url.lower() in ['quit', 'exit', 'q']:
                    break
                if url:
                    expand_single_url(url, timeout=args.timeout, verbose=args.verbose, 
                                     use_browser=args.browser, aggressive=args.aggressive,
                                     full_coverage=args.full_coverage, comprehensive=args.comprehensive)
            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except Exception as e:
                logger.error(f"Error: {e}")


if __name__ == "__main__":
    main()
