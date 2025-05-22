import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib


df = pd.read_csv('./ml_models/XSS_dataset.csv')
print(df.head())
print(df['Label'].value_counts())


vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df['Sentence'])
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier()
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

joblib.dump(clf, './ml_models/xss_rf_model.pkl')
joblib.dump(vectorizer, './ml_models/xss_vectorizer.pkl')
