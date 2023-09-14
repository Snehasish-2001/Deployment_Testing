import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import re
from urllib.parse import urlparse

# Step 1: Load the dataset (you should prepare your dataset)
data = pd.read_csv("malicious_phish.csv.").sample(10000) # Replace with your dataset

# Step 2: Data Preprocessing and Feature Engineering
def preprocess_url(url):
    # Preprocess the URL and extract features
    domain = urlparse(url).netloc
    path = urlparse(url).path

    # Feature extraction
    url_length = len(url)
    domain_length = len(domain)
    num_subdomains = len(domain.split('.'))
    is_ip_address = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) else 0
    has_at_symbol = 1 if '@' in url else 0
    has_https = 1 if 'https' in url else 0
    has_http = 1 if 'http' in url else 0
    has_www = 1 if 'www' in url else 0
    has_hyphen = 1 if '-' in domain else 0
    num_dots = domain.count('.')
    num_digits = sum(c.isdigit() for c in url)
    num_special_chars = sum(not c.isalnum() for c in url)
    phishing_keywords = ['secure', 'account', 'login', 'verify', 'bank', 'paypal']
    has_phishing_keywords = any(keyword in url for keyword in phishing_keywords)
    path_length = len(path)
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

data['url_features'] = data['url'].apply(preprocess_url)

# Step 3: Data Splitting
X = pd.DataFrame(data['url_features'].tolist(), columns=[
    'url_length', 'domain_length', 'num_subdomains', 'is_ip_address', 'has_at_symbol', 'has_https', 'has_http',
    'has_www', 'has_hyphen', 'num_dots', 'num_digits', 'num_special_chars', 'has_phishing_keywords', 'path_length',
    'has_exe', 'has_zip', 'has_pdf', 'has_doc', 'has_php', 'has_html'
])
y = data['type'].values  # Target variable

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 4: Model Selection
model = RandomForestClassifier(n_estimators=100, random_state=42)

# Step 5: Model Training
model.fit(X_train, y_train)

# Step 6: Model Evaluation
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.2f}")

print(classification_report(y_test, y_pred))

# Step 8: Model Deployment
# For deployment, you'd typically use a web framework like Flask or Django and create an API for real-time predictions.

import pickle

# Save the trained model to a file
with open("phishing_model.pkl", "wb") as model_file:
    pickle.dump(model, model_file)
