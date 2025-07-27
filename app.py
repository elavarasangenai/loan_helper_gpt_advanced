from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import uuid
import bcrypt
from supabase import create_client, Client
import shutil
from dotenv import load_dotenv
load_dotenv()
from langchain_community.document_loaders import PyPDFLoader, Docx2txtLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAI
from langchain.chains import RetrievalQA

app = Flask(__name__)
CORS(app)

# Secret key for session handling
app.secret_key = os.environ.get("SECRET_KEY", "mysecret")
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Supabase config
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


ALLOWED_EXTENSIONS = {'pdf', 'docx'}

llm = OpenAI(temperature=0)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def handle_error(e):
    return jsonify({"error": str(e)}), 500

# ---------------------- Register ----------------------
@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        name = data.get("name")
        mobile = data.get("mobile")
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        if not all([name, mobile, password, confirm_password]):
            return jsonify({"error": "All fields are required."}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match."}), 400

        existing = supabase.table("users").select("*").eq("mobile", mobile).execute()
        if existing.data:
            return jsonify({"error": "Mobile already registered."}), 400

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        supabase.table("users").insert({
            "name": name,
            "mobile": mobile,
            "password": hashed_pw
        }).execute()

        return jsonify({"message": "User registered successfully."})
    except Exception as e:
        return handle_error(e)

# ---------------------- Login ----------------------
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        mobile = data.get("mobile")
        password = data.get("password")

        if not all([mobile, password]):
            return jsonify({"error": "Mobile and password required."}), 400

        user = supabase.table("users").select("*").eq("mobile", mobile).execute()
        if not user.data:
            return jsonify({"error": "Invalid credentials."}), 401

        stored_hash = user.data[0]['password']
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            return jsonify({"error": "Invalid credentials."}), 401

        session['user_id'] = user.data[0]['id']
        return jsonify({"message": "Login successful."})
    except Exception as e:
        return handle_error(e)

# ---------------------- Logout ----------------------
@app.route("/logout", methods=["POST"])
def logout():
    session.pop('user_id', None)
    return jsonify({"message": "Logged out successfully."})

# ---------------------- Upload Document ----------------------
@app.route("/upload", methods=["POST"])
def upload_document():
    try:
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized."}), 401

        if 'file' not in request.files:
            return jsonify({"error": "No file part."}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected."}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_name = f"{uuid.uuid4()}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
            file.save(filepath)

            # Save metadata to Supabase
            supabase.table("documents").insert({
                "user_id": session['user_id'],
                "filename": filename,
                "filepath": filepath
            }).execute()

            # Process the document and store embeddings
            process_document(filepath, session['user_id'], filename)

            return jsonify({"message": "File uploaded and processed successfully."})

        return jsonify({"error": "File type not allowed."}), 400
    except Exception as e:
        return handle_error(e)

# ---------------------- My Documents ----------------------
@app.route("/my-documents", methods=["GET"])
def my_documents():
    try:
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized."}), 401

        docs = supabase.table("documents").select("*").eq("user_id", session['user_id']).execute()
        return jsonify({"documents": docs.data})
    except Exception as e:
        return handle_error(e)

# ---------------------- Delete Document ----------------------
@app.route("/delete-document/<filename>", methods=["DELETE"])
def delete_document(filename):
    try:
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized."}), 401

        # Delete from Supabase
        response = supabase.table("documents").select("*").eq("user_id", session['user_id']).eq("filename", filename).execute()
        if not response.data:
            return jsonify({"error": "Document not found."}), 404

        file_record = response.data[0]
        supabase.table("documents").delete().eq("id", file_record['id']).execute()

        # Delete file from local storage
        if os.path.exists(file_record['filepath']):
            os.remove(file_record['filepath'])

        # Delete FAISS index
        index_path = f"faiss_index/user_{session['user_id']}_{filename}"
        if os.path.exists(index_path):
            shutil.rmtree(index_path)

        return jsonify({"message": "Document deleted successfully."})
    except Exception as e:
        return handle_error(e)

# ---------------------- Document Processor ----------------------
def process_document(filepath, user_id, filename):
    ext = filepath.rsplit('.', 1)[1].lower()
    if ext == 'pdf':
        loader = PyPDFLoader(filepath)
    elif ext == 'docx':
        loader = Docx2txtLoader(filepath)
    else:
        raise ValueError("Unsupported file format")

    documents = loader.load()
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    chunks = splitter.split_documents(documents)

    embeddings = OpenAIEmbeddings()
    index_path = f"faiss_index/user_{user_id}_{filename}"
    vectordb = FAISS.from_documents(chunks, embeddings)
    vectordb.save_local(index_path)

# ---------------------- Summarize Document ----------------------
@app.route("/summarize/<filename>", methods=["GET"])
def summarize_document(filename):
    try:
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized."}), 401

        index_path = f"faiss_index/user_{session['user_id']}_{filename}"
        db = FAISS.load_local(index_path, OpenAIEmbeddings(), allow_dangerous_deserialization=True)

        retriever = db.as_retriever()

        chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)
        prompt = """
        You're a financial assistant. Analyze this loan document and extract key clauses, borrower obligations, and risky terms.
        Tag each point as 🟢 Safe, 🟡 Caution, or 🔴 Risk.
        Respond in bullet points with simple English.
        """
        summary = chain.run(prompt)
        return jsonify({"summary": summary})
    except Exception as e:
        return handle_error(e)

# ---------------------- Ask Question ----------------------
@app.route("/ask", methods=["POST"])
def ask_question():
    try:
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized."}), 401

        data = request.get_json()
        question = data.get("question")
        filename = data.get("filename")
        if not question or not filename:
            return jsonify({"error": "Both question and filename are required."}), 400

        index_path = f"faiss_index/user_{session['user_id']}_{filename}"
        db = FAISS.load_local(index_path, OpenAIEmbeddings(), allow_dangerous_deserialization=True)

        retriever = db.as_retriever()

        qa_chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever, return_source_documents=False)
        answer = qa_chain.run(question)

        return jsonify({"answer": answer})
    except Exception as e:
        return handle_error(e)

if __name__ == '__main__':
    app.run(debug=True)
