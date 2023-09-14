from flask import Flask, request, jsonify ,render_template
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from urllib.parse import urlparse

app = Flask(__name__)

# Load the trained model
import pickle

# Load the trained model from the file
with open("phishing_model.pkl", "rb") as model_file:
    model = pickle.load(model_file)


@app.route('/')
def index():
    return  render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.json['url']

       
        # Preprocess the URL and extract features (you should implement this)
        import re
        from urllib.parse import urlparse

        def extract_features(url):
            # 1. URL length
            url_length = len(url)

            # 2. Domain length
            domain = urlparse(url).netloc
            domain_length = len(domain)

            # 3. Number of subdomains
            subdomains = domain.split('.')
            num_subdomains = len(subdomains)

            # 4. Use of IP address in URL
            is_ip_address = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) else 0

            # 5. Use of '@' symbol in URL
            has_at_symbol = 1 if '@' in url else 0

            # 6. Use of 'https' in URL
            has_https = 1 if 'https' in url else 0

            # 7. Use of 'http' in URL
            has_http = 1 if 'http' in url else 0

            # 8. Use of 'www' in URL
            has_www = 1 if 'www' in url else 0

            # 9. Use of hyphen '-' in domain
            has_hyphen = 1 if '-' in domain else 0

            # 10. Number of dots in domain
            num_dots = domain.count('.')

            # 11. Number of digits in URL
            num_digits = sum(c.isdigit() for c in url)

            # 12. Number of special characters in URL
            num_special_chars = sum(not c.isalnum() for c in url)

            # 13. Presence of known phishing keywords in URL
            phishing_keywords = ['secure', 'account', 'login', 'verify', 'bank', 'paypal']
            has_phishing_keywords = any(keyword in url for keyword in phishing_keywords)

            # 14. URL path length
            path = urlparse(url).path
            path_length = len(path)

            # 15-20. Presence of specific file extensions in the URL
            extensions = ['.exe', '.zip', '.pdf', '.doc', '.php', '.html']
            has_extensions = [1 if extension in url else 0 for extension in extensions]

            # Combine all features into a feature vector
            feature_vector = [
                url_length,
                domain_length,
                num_subdomains,
                is_ip_address,
                has_at_symbol,
                has_https,
                has_http,
                has_www,
                has_hyphen,
                num_dots,
                num_digits,
                num_special_chars,
                has_phishing_keywords,
                path_length,
                *has_extensions
            ]

            return feature_vector

        

            
                # For simplicity, let's assume you have a function extract_features(url)
        features = extract_features(url)

                # Make a prediction
        prediction = model.predict([features])

        # Return the prediction as JSON
        response = {
            'url': url,
            'is_phishing': bool(prediction[0])
        }
        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
