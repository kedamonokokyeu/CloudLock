"""
CloudLock Web Scraping Module
Detects potential data leaks by searching for S3 bucket names across public sources
"""

import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime
import json

class WebLeakDetector:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.leak_sources = []
        
    def search_github(self, bucket_name):
        """
        Search GitHub for potential bucket name leaks
        Returns: List of potential leak URLs
        """
        try:
            # GitHub Code Search API
            url = f"https://api.github.com/search/code?q={bucket_name}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                total_count = data.get('total_count', 0)
                
                if total_count > 0:
                    leaks = []
                    for item in data.get('items', [])[:5]:  # Limit to first 5 results
                        leaks.append({
                            'source': 'GitHub',
                            'url': item.get('html_url'),
                            'repository': item.get('repository', {}).get('full_name'),
                            'path': item.get('path')
                        })
                    return leaks
            
            return []
            
        except Exception as e:
            print(f"GitHub search error for {bucket_name}: {e}")
            return []
    
    def search_pastebin(self, bucket_name):
        """
        Search Pastebin for bucket name mentions
        Note: Pastebin doesn't have a free search API, so this is a placeholder
        """
        try:
            # This is a simulated search - in production you'd use Pastebin's API
            # or web scraping with proper rate limiting
            print(f"Checking Pastebin for: {bucket_name}")
            
            # Placeholder - in real implementation, you'd scrape recent pastes
            # or use a paid API service
            return []
            
        except Exception as e:
            print(f"Pastebin search error: {e}")
            return []
    
    def search_google_dorks(self, bucket_name):
        """
        Use Google dorks to find exposed bucket references
        Warning: Use carefully to avoid rate limiting
        """
        try:
            # Google Custom Search API (requires API key)
            # This is a placeholder - you'd need to set up Google Custom Search
            queries = [
                f'"{bucket_name}" site:github.com',
                f'"{bucket_name}" site:pastebin.com',
                f'"{bucket_name}" filetype:json',
                f'"{bucket_name}" filetype:txt'
            ]
            
            print(f"Running Google dork searches for: {bucket_name}")
            # In production, implement actual Google Custom Search API calls
            
            return []
            
        except Exception as e:
            print(f"Google search error: {e}")
            return []
    
    def check_public_s3_access(self, bucket_name):
        """
        Try to access the bucket directly via HTTP to check if it's publicly listable
        """
        try:
            urls_to_check = [
                f"http://{bucket_name}.s3.amazonaws.com/",
                f"https://{bucket_name}.s3.amazonaws.com/",
                f"http://s3.amazonaws.com/{bucket_name}/",
            ]
            
            for url in urls_to_check:
                try:
                    response = requests.get(url, timeout=5)
                    
                    # If we get XML response, bucket is publicly accessible
                    if response.status_code == 200 and 'xml' in response.headers.get('content-type', '').lower():
                        return {
                            'publicly_accessible': True,
                            'url': url,
                            'status_code': response.status_code,
                            'severity': 'CRITICAL'
                        }
                    
                except requests.exceptions.RequestException:
                    continue
            
            return {
                'publicly_accessible': False,
                'severity': 'SAFE'
            }
            
        except Exception as e:
            print(f"Public access check error: {e}")
            return {'publicly_accessible': False, 'error': str(e)}
    
    def scan_bucket_for_leaks(self, bucket_name):
        """
        Main function to scan a bucket for potential data leaks
        """
        print(f"\nScanning for external leaks: {bucket_name}")
        
        results = {
            'bucket_name': bucket_name,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'leaks_found': False,
            'severity': 'SAFE',
            'sources': []
        }
        
        # 1. Check if bucket is publicly accessible via HTTP
        print(" Checking public HTTP access...")
        public_check = self.check_public_s3_access(bucket_name)
        if public_check.get('publicly_accessible'):
            results['leaks_found'] = True
            results['severity'] = 'CRITICAL'
            results['sources'].append({
                'type': 'Direct Public Access',
                'details': public_check
            })
            print(" CRITICAL: Bucket is publicly accessible!")
        else:
            print("Bucket not publicly accessible via HTTP")
        
        # 2. Search GitHub
        print("Searching GitHub...")
        time.sleep(1)  # Rate limiting
        github_results = self.search_github(bucket_name)
        if github_results:
            results['leaks_found'] = True
            results['severity'] = 'HIGH' if results['severity'] != 'CRITICAL' else 'CRITICAL'
            results['sources'].append({
                'type': 'GitHub',
                'count': len(github_results),
                'leaks': github_results
            })
            print(f"Found {len(github_results)} potential leaks on GitHub!")
        else:
            print("No leaks found on GitHub")
        
        # 3. Additional searches (Pastebin, etc.)
        # Uncomment when you have API access
        # pastebin_results = self.search_pastebin(bucket_name)
        
        # Set final severity
        if not results['leaks_found']:
            results['severity'] = 'SAFE'
        
        return results
    
    def scan_all_buckets(self, bucket_names):
        """
        Scan multiple buckets for leaks
        """
        all_results = []
        
        print("\n" + "="*30)
        print("CLOUDLOCK WEB SCRAPING LEAK DETECTION")
        print("="*30)
        
        for i, bucket_name in enumerate(bucket_names, 1):
            print(f"\n[{i}/{len(bucket_names)}] Scanning: {bucket_name}")
            
            results = self.scan_bucket_for_leaks(bucket_name)
            all_results.append(results)
            
            # Rate limiting between buckets
            if i < len(bucket_names):
                time.sleep(2)
        
        # Summary
        print("\n" + "="*30)
        print("LEAK DETECTION SUMMARY")
        print("="*30)
        
        total_leaks = sum(1 for r in all_results if r['leaks_found'])
        critical = sum(1 for r in all_results if r['severity'] == 'CRITICAL')
        high = sum(1 for r in all_results if r['severity'] == 'HIGH')
        
        print(f"\nTotal Buckets Scanned: {len(bucket_names)}")
        print(f"Buckets with Leaks: {total_leaks}")
        print(f" - Critical: {critical}")
        print(f" - High: {high}")
        print(f" - Safe: {len(bucket_names) - total_leaks}")
        
        if total_leaks > 0:
            print("\nATTENTION REQUIRED:")
            for result in all_results:
                if result['leaks_found']:
                    print(f"\n{result['bucket_name']} [{result['severity']}]")
                    for source in result['sources']:
                        print(f"{source['type']}: Found in {source.get('count', 1)} location(s)")
        else:
            print("\nNo external leaks detected! All buckets appear safe.")
        
        return all_results
    
    def export_leak_report(self, results, filename=None):
        """
        Export leak detection results to JSON
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'cloudlock_leak_detection_{timestamp}.json'
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nLeak detection report saved: {filename}")
        return filename


def test_leak_detector():

    detector = WebLeakDetector()
    

    test_buckets = [
        "my-test-bucket-12345",
        "public-demo-bucket"
    ]
    
    results = detector.scan_all_buckets(test_buckets)
    detector.export_leak_report(results)

if __name__ == "__main__":
    test_leak_detector()