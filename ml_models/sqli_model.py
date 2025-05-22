import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Embedding, Dropout
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

data = pd.read_csv("./ml_models/Modified_SQL_Dataset.csv")

print(data.head())

X = data["Query"]  # SQL queries
y = data["Label"]      # 0 = benign, 1 = malicious

# Step 2: Preprocess Data

tokenizer = Tokenizer(num_words=10000)  # Limit vocabulary size to 10,000
tokenizer.fit_on_texts(X)
X_tokenized = tokenizer.texts_to_sequences(X)

# Pad sequences to ensure uniform length
max_sequence_length = 100  # Set a maximum sequence length
X_padded = pad_sequences(X_tokenized, maxlen=max_sequence_length, padding='post')

X_train, X_test, y_train, y_test = train_test_split(X_padded, y, test_size=0.2, random_state=42)

# CNN Model
model = Sequential([
    Embedding(input_dim=10000, output_dim=128, input_length=max_sequence_length),  # Embedding layer
    Conv1D(filters=64, kernel_size=3, activation='relu'),  # Convolutional layer
    MaxPooling1D(pool_size=2),  # Max pooling layer
    Dropout(0.5),  # Dropout for regularization
    Flatten(),  # Flatten the feature maps
    Dense(64, activation='relu'),  # Fully connected layer
    Dropout(0.5),  # Dropout for regularization
    Dense(1, activation='sigmoid')  # Output layer for binary classification
])

# Compile the model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Step 4: Train the Model
history = model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.2)

# Step 5: Evaluate the Model
y_pred = (model.predict(X_test) > 0.5).astype("int32")
print("Classification Report:\n", classification_report(y_test, y_pred))

# Step 6: Test on New Inputs
new_queries = ["SELECT * FROM users WHERE username='admin' AND password='123'",
               "' OR 1=1 --",
               "DROP TABLE users; --",
               "Safe query with no injection"]
new_queries_tokenized = tokenizer.texts_to_sequences(new_queries)
new_queries_padded = pad_sequences(new_queries_tokenized, maxlen=max_sequence_length, padding='post')

predictions = model.predict(new_queries_padded)
for query, pred in zip(new_queries, predictions):
    print(f"Query: {query}")
    print("SQL Injection Detected!" if pred > 0.5 else "Query is Safe.")
    print("-" * 50)

model.save('cnn_sqli_model.keras')

