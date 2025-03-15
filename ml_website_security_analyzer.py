import re
import socket
import ssl
import urllib.parse
import requests
from datetime import datetime
import whois
import tldextract
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import pickle

class WebsiteSecurityAnalyzer:
    def __init__(self, use_ml=True):
        self.use_ml = use_ml
        # Known malicious patterns in URLs
        self.suspicious_patterns = [
            r'login.*\.php',
            r'secure.*\.php',
            r'account.*\.php',
            r'admin.*\.php',
            r'bank.*\.php',
            r'update.*\.php',
            r'wp-includes',
            r'download.*\.php',
            r'\.exe$',
            r'(bitcoin|btc|crypto|wallet|blockchain)',
            r'(free.*money|prize|winner)',
            r'password.*reset',
        ]
        
        # Common TLDs associated with abuse
        self.suspicious_tlds = [
            '.xyz', '.top', '.club', '.online', '.site', '.tk', '.ml', '.ga', '.cf'
        ]
        
        # Reputable domains (simplified for example)
        self.reputable_domains = [
            'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'github.com', 'youtube.com'
        ]
        
        # Initialize ML model
        if self.use_ml:
            self.model_file = "malicious_website_model.pkl"
            if os.path.exists(self.model_file):
                self.ml_model = joblib.load(self.model_file)
                print(f"Loaded existing ML model from {self.model_file}")
            else:
                print("No existing model found. Training a new one with sample data.")
                self.ml_model = self._train_initial_model()
                joblib.dump(self.ml_model, self.model_file)
                print(f"Saved new ML model to {self.model_file}")

    def _train_initial_model(self):
        """
        Train an initial model with sample data
        In a real-world scenario, you would use a large labeled dataset
        """
        # Features: [uses_https, suspicious_patterns_count, domain_age_days, uses_suspicious_tld, 
        #           domain_length, uses_ip, has_redirects, subdomains_count, url_length]
        
        # Sample training data (simplified for demonstration)
        # Format: [features], label (0 = benign, 1 = malicious)
        X = [
            # Benign examples
            [1, 0, 3650, 0, 10, 0, 0, 1, 30],      # google.com
            [1, 0, 5840, 0, 12, 0, 0, 1, 32],      # facebook.com
            [1, 0, 2190, 0, 15, 0, 0, 2, 45],      # support.apple.com
            [1, 0, 4380, 0, 11, 0, 0, 1, 29],      # amazon.com
            [1, 0, 1825, 0, 14, 0, 0, 3, 50],      # developer.mozilla.org
            [1, 0, 3000, 0, 13, 0, 0, 1, 33],      # microsoft.com
            [1, 0, 2738, 0, 12, 0, 0, 2, 38],      # github.com
            [1, 0, 4100, 0, 11, 0, 0, 1, 31],      # twitter.com
            [1, 1, 1800, 0, 16, 0, 0, 2, 42],      # mail.university.edu
            [1, 0, 2500, 0, 14, 0, 0, 1, 35],      # wikipedia.org
            
            # Malicious examples
            [0, 3, 2, 1, 35, 0, 1, 3, 120],        # very-suspicious-login.xyz
            [0, 2, 5, 0, 40, 1, 1, 0, 80],         # 192.168.1.1/phishing
            [0, 4, 10, 1, 45, 0, 1, 4, 130],       # a.b.c.d.suspicious.online/login
            [0, 3, 15, 1, 28, 0, 1, 2, 90],        # free-bitcoin-wallet.top
            [1, 2, 20, 0, 50, 0, 1, 3, 100],       # secure-bank-login.com-secure.net
            [0, 5, 3, 1, 55, 0, 0, 5, 140],        # my.secure.login.password.reset.club
            [0, 2, 8, 1, 30, 1, 1, 0, 70],         # 10.0.0.1/admin.php
            [0, 3, 12, 1, 25, 0, 1, 2, 85],        # free-prize-winner.ml
            [0, 4, 5, 0, 42, 0, 1, 3, 110],        # update-your-account-now.com
            [1, 3, 7, 1, 38, 0, 1, 4, 95],         # a.b.c.d.paypal-secure.xyz
        ]
        
        y = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        
        # Train a Random Forest classifier
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        
        return model

    def analyze_url(self, url):
        """
        Analyzes a URL for potential security threats
        Returns a dictionary of security checks and an overall risk score
        """
        # Standardize URL format
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Parse URL
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        full_path = parsed_url.path
        
        # Extract domain parts
        ext = tldextract.extract(domain)
        base_domain = f"{ext.domain}.{ext.suffix}"
        tld = f".{ext.suffix}"
        
        # Initialize results
        results = {
            'url': url,
            'domain': domain,
            'checks': {},
            'risk_score': 0,
            'risk_level': '',
            'details': [],
            'ml_prediction': None,
            'feature_importances': {}
        }
        
        # Run security checks
        self._check_https(url, results)
        self._check_suspicious_patterns(url, full_path, results)
        self._check_domain_age(domain, results)
        self._check_suspicious_tld(tld, results)
        self._check_domain_reputation(base_domain, results)
        self._check_domain_length(domain, results)
        self._check_ip_url(domain, results)
        self._check_redirects(url, results)
        
        # Calculate initial risk score
        heuristic_score = sum(results['checks'].values())
        results['heuristic_score'] = min(100, max(0, heuristic_score))
        
        # Use machine learning model if available
        if self.use_ml:
            ml_result = self._ml_prediction(url, results)
            results['ml_prediction'] = ml_result['prediction']
            results['feature_importances'] = ml_result['feature_importances']
            
            # Blend heuristic and ML scores (70% ML, 30% heuristic)
            ml_score = 100 if ml_result['prediction'] == 1 else 0
            results['risk_score'] = int(0.3 * results['heuristic_score'] + 0.7 * ml_score)
        else:
            results['risk_score'] = results['heuristic_score']
        
        # Determine risk level
        if results['risk_score'] >= 70:
            results['risk_level'] = 'High Risk'
        elif results['risk_score'] >= 40:
            results['risk_level'] = 'Medium Risk'
        else:
            results['risk_level'] = 'Low Risk'
            
        return results

    def _ml_prediction(self, url, results):
        """Use the ML model to predict if a URL is malicious"""
        # Extract features for ML prediction
        features = self._extract_features(url, results)
        
        # Make prediction
        prediction = self.ml_model.predict([features])[0]
        
        # Get feature importances
        feature_names = [
            'uses_https', 'suspicious_patterns_count', 'domain_age_days', 
            'uses_suspicious_tld', 'domain_length', 'uses_ip', 
            'has_redirects', 'subdomains_count', 'url_length'
        ]
        
        importances = dict(zip(feature_names, self.ml_model.feature_importances_))
        
        # Add ML-specific details
        if prediction == 1:
            results['details'].append("Machine learning model classified this URL as potentially malicious")
            
            # Add top 3 most important features for this prediction
            sorted_importances = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:3]
            for feature, importance in sorted_importances:
                results['details'].append(f"Important factor: {feature.replace('_', ' ')} (importance: {importance:.2f})")
        
        return {
            'prediction': prediction,
            'feature_importances': importances
        }
    
    def _extract_features(self, url, results):
        """Extract features for machine learning model"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # Extract domain parts
        ext = tldextract.extract(domain)
        tld = f".{ext.suffix}"
        
        # Count suspicious patterns
        suspicious_pattern_count = 0
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_pattern_count += 1
        
        # Count subdomains
        subdomain_count = len(domain.split('.')) - 2 if domain.count('.') > 0 else 0
        
        # Convert domain age to days (with a cap)
        domain_age = 0
        if 'domain_age' in results.get('checks', {}):
            domain_age = max(0, 30 - results['checks']['domain_age']) * 100  # Approximate days based on score
        
        # Features in the expected order
        features = [
            1 if url.startswith('https://') else 0,              # uses_https
            suspicious_pattern_count,                            # suspicious_patterns_count
            domain_age,                                          # domain_age_days
            1 if tld in self.suspicious_tlds else 0,             # uses_suspicious_tld
            len(domain),                                         # domain_length
            1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) else 0,  # uses_ip
            1 if results.get('checks', {}).get('redirect', 0) > 0 else 0,  # has_redirects
            subdomain_count,                                     # subdomains_count
            len(url)                                             # url_length
        ]
        
        return features

    def _check_https(self, url, results):
        """Check if website uses HTTPS"""
        has_https = url.startswith('https://')
        results['checks']['https'] = 0 if has_https else 10
        if not has_https:
            results['details'].append("Website does not use HTTPS encryption")

    def _check_suspicious_patterns(self, url, path, results):
        """Check for suspicious patterns in URL"""
        score = 0
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                score += 15
                results['details'].append(f"URL contains suspicious pattern: {pattern}")
                
        # Check for excessive subdomains
        subdomain_count = len(url.split('.')) - 2
        if subdomain_count > 3:
            score += 10
            results['details'].append(f"URL contains excessive subdomains ({subdomain_count})")
            
        # Check for URL length (very long URLs are suspicious)
        if len(url) > 100:
            score += 10
            results['details'].append(f"Unusually long URL ({len(url)} characters)")
            
        results['checks']['patterns'] = min(score, 30)  # Cap at 30 points

    def _check_domain_age(self, domain, results):
        """Check domain registration age"""
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            
            # Handle different return types from whois
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                domain_age_days = (datetime.now() - creation_date).days
                
                if domain_age_days < 30:
                    results['checks']['domain_age'] = 20
                    results['details'].append(f"Domain is very new ({domain_age_days} days old)")
                elif domain_age_days < 90:
                    results['checks']['domain_age'] = 10
                    results['details'].append(f"Domain is relatively new ({domain_age_days} days old)")
                else:
                    results['checks']['domain_age'] = 0
            else:
                results['checks']['domain_age'] = 10
                results['details'].append("Unable to determine domain age")
                
        except Exception:
            results['checks']['domain_age'] = 5
            results['details'].append("Unable to verify domain registration information")

    def _check_suspicious_tld(self, tld, results):
        """Check if TLD is commonly associated with abuse"""
        if tld in self.suspicious_tlds:
            results['checks']['tld'] = 15
            results['details'].append(f"Domain uses suspicious TLD: {tld}")
        else:
            results['checks']['tld'] = 0

    def _check_domain_reputation(self, domain, results):
        """Check if domain is in list of reputable domains"""
        if domain in self.reputable_domains:
            results['checks']['reputation'] = -30  # Significant bonus for known good domains
            results['details'].append("Domain has good reputation")
        else:
            results['checks']['reputation'] = 0

    def _check_domain_length(self, domain, results):
        """Check for unusually long domain names"""
        if len(domain) > 30:
            results['checks']['domain_length'] = 10
            results['details'].append(f"Unusually long domain name ({len(domain)} characters)")
        else:
            results['checks']['domain_length'] = 0

    def _check_ip_url(self, domain, results):
        """Check if URL uses IP address instead of domain name"""
        ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
        if re.match(ip_pattern, domain):
            results['checks']['ip_url'] = 25
            results['details'].append("URL uses IP address instead of domain name")
        else:
            results['checks']['ip_url'] = 0

    def _check_redirects(self, url, results):
        """Check if URL immediately redirects to another domain"""
        try:
            response = requests.head(url, allow_redirects=False, timeout=3)
            if response.status_code in (301, 302, 303, 307, 308):
                if 'Location' in response.headers:
                    redirect_url = response.headers['Location']
                    parsed_original = urllib.parse.urlparse(url)
                    parsed_redirect = urllib.parse.urlparse(redirect_url)
                    
                    # Check if redirect goes to a different domain
                    if parsed_original.netloc != parsed_redirect.netloc:
                        results['checks']['redirect'] = 20
                        results['details'].append(f"URL redirects to different domain: {parsed_redirect.netloc}")
                    else:
                        results['checks']['redirect'] = 0
            else:
                results['checks']['redirect'] = 0
        except Exception:
            results['checks']['redirect'] = 5
            results['details'].append("Unable to check URL redirects")

    def retrain_model(self, urls_with_labels):
        """
        Retrain the ML model with new data
        urls_with_labels: list of tuples (url, label) where label is 0 (benign) or 1 (malicious)
        """
        if not self.use_ml:
            print("ML functionality is disabled")
            return False
            
        try:
            # Extract features for each URL
            X = []
            y = []
            
            for url, label in urls_with_labels:
                # Get initial results using heuristic methods
                results = self.analyze_url(url)
                
                # Extract features
                features = self._extract_features(url, results)
                X.append(features)
                y.append(label)
            
            # Retrain the model
            self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.ml_model.fit(X, y)
            
            # Save the model
            joblib.dump(self.ml_model, self.model_file)
            print(f"Model retrained successfully with {len(urls_with_labels)} new examples")
            return True
            
        except Exception as e:
            print(f"Error retraining model: {str(e)}")
            return False


def main():
    analyzer = WebsiteSecurityAnalyzer(use_ml=True)
    
    print("╔═══════════════════════════════════════════════╗")
    print("║ ML-Enhanced Website Security Analyzer         ║")
    print("║ Malicious Site Detection Tool                 ║")
    print("╚═══════════════════════════════════════════════╝")
    print("This tool uses both heuristic rules and machine learning")
    print("to identify potentially malicious websites.")
    
    while True:
        print("\nOptions:")
        print("1. Analyze a URL")
        print("2. Provide feedback on URL (to improve ML model)")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == '1':
            url = input("\nEnter a URL to analyze: ")
            
            try:
                print("\nAnalyzing URL:", url)
                print("Please wait...\n")
                
                results = analyzer.analyze_url(url)
                
                print("═══════════════════════════════════════════════")
                print(f"ANALYSIS RESULTS FOR: {results['url']}")
                print("═══════════════════════════════════════════════")
                print(f"RISK SCORE: {results['risk_score']}/100")
                print(f"RISK LEVEL: {results['risk_level']}")
                
                if results.get('ml_prediction') is not None:
                    print(f"ML PREDICTION: {'Malicious' if results['ml_prediction'] == 1 else 'Benign'}")
                
                print("───────────────────────────────────────────────")
                print("DETAILS:")
                
                for detail in results['details']:
                    print(f"• {detail}")
                    
                if not results['details']:
                    print("• No specific security issues detected")
                    
                print("\nRECOMMENDATION:")
                if results['risk_level'] == 'High Risk':
                    print("✖ AVOID THIS WEBSITE! High probability of malicious content.")
                elif results['risk_level'] == 'Medium Risk':
                    print("⚠ PROCEED WITH CAUTION. Some suspicious indicators detected.")
                else:
                    print("✓ LIKELY SAFE. Low risk indicators detected.")
                    
                print("═══════════════════════════════════════════════\n")
                
            except Exception as e:
                print(f"Error analyzing URL: {str(e)}")
                
        elif choice == '2':
            url = input("\nEnter the URL you want to provide feedback on: ")
            
            while True:
                label_input = input("Is this URL malicious? (y/n): ").lower()
                if label_input in ['y', 'n']:
                    break
                print("Please enter 'y' or 'n'")
            
            label = 1 if label_input == 'y' else 0
            
            # Retrain model with the new data point
            success = analyzer.retrain_model([(url, label)])
            
            if success:
                print("Thank you for your feedback! The model has been updated.")
            else:
                print("There was an error updating the model. Your feedback was not incorporated.")
            
        elif choice == '3':
            print("\nExiting. Thank you for using the Website Security Analyzer!")
            break
            
        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
