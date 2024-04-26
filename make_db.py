from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient('mongodb://admin:admin@0.0.0.0:27017/')
db = client['mydatabase']  # Use or create a database
print(f"Database: {db.name}")
collection = db['mycollection']  # Use or create a collection

# Insert Data
post = {"author": "John", "text": "My first blog post!", "tags": ["mongodb", "python", "pymongo"]}
post_id = collection.insert_one(post).inserted_id
print(f"Post ID: {post_id}")

# Retrieve Data
for post in collection.find():
    print(post)
