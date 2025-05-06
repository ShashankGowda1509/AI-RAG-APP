from flask import Flask, render_template, request, redirect, url_for, send_file, session, flash, jsonify
import os
import sqlite3
import io
import re
import bcrypt
import logging
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from datetime import datetime, timedelta
import pdfplumber
from langchain.schema import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.retrievers import BM25Retriever
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from langchain_ollama import ChatOllama

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", 'default_secret_key')  # Use environment variable in production

# Add current date to templates
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Email configuration for password reset
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'youremail@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your_app_password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'youremail@gmail.com')
mail = Mail(app)

# Serializer for generating secure tokens
serializer = URLSafeTimedSerializer(app.secret_key)

def init_db():
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        file_data BLOB NOT NULL,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        content_delta TEXT,
        content_html TEXT,
        last_edited TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        file_data BLOB,
        mimetype TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT,
        expiry TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS pdf_chunks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        upload_id INTEGER,
        chunk_text TEXT,
        FOREIGN KEY (upload_id) REFERENCES uploads(id)
    )''')
    conn.commit()
    conn.close()

# Initialize the database on startup
init_db()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('files.db')
        c = conn.cursor()
        c.execute("SELECT id, username, password FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials', 'error')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            conn = sqlite3.connect('files.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                    (username, hashed_password, email))
            conn.commit()
            conn.close()
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        conn = sqlite3.connect('files.db')
        c = conn.cursor()
        c.execute("SELECT id, email FROM users WHERE username=?", (username,))
        user = c.fetchone()
        if user:
            user_id, email = user
            token = serializer.dumps(email, salt='password-reset-salt')
            expiry = datetime.utcnow() + timedelta(minutes=30)
            c.execute("INSERT INTO reset_tokens (user_id, token, expiry) VALUES (?, ?, ?)",
                    (user_id, token, expiry))
            conn.commit()
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f"Click the link to reset your password (valid for 30 minutes): {reset_link}"
            mail.send(msg)
        conn.close()
        flash('If an account exists with this username, a reset link has been sent to the registered email.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("SELECT user_id, expiry FROM reset_tokens WHERE token=?", (token,))
    token_data = c.fetchone()
    if not token_data or datetime.utcnow() > datetime.strptime(token_data[1], '%Y-%m-%d %H:%M:%S.%f'):
        c.execute("DELETE FROM reset_tokens WHERE token=?", (token,))
        conn.commit()
        conn.close()
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        c.execute("UPDATE users SET password=? WHERE id=?", (hashed_password, token_data[0]))
        c.execute("DELETE FROM reset_tokens WHERE token=?", (token,))
        conn.commit()
        conn.close()
        flash('Password reset successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    conn.close()
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('current_pdf_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access the dashboard', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("SELECT id, filename, upload_date FROM uploads WHERE user_id=? ORDER BY upload_date DESC", (session['user_id'],))
    files = c.fetchall()
    
    c.execute("SELECT id, title, last_edited FROM notes WHERE user_id=? ORDER BY last_edited DESC", (session['user_id'],))
    notes = c.fetchall()
    
    conn.close()
    return render_template('user_dashboard.html', files=files, notes=notes)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        flash('Please login to upload files', 'error')
        return redirect(url_for('login'))
    
    filename = request.form['filename']
    file = request.files['file']
    
    if file and file.filename.endswith('.pdf'):
        file_data = file.read()
        conn = sqlite3.connect('files.db')
        c = conn.cursor()
        c.execute("INSERT INTO uploads (user_id, filename, file_data) VALUES (?, ?, ?)",
                (session['user_id'], filename, file_data))
        upload_id = c.lastrowid
        
        # Process PDF into chunks and store
        try:
            # Use pdfplumber for better extraction
            pdf = pdfplumber.open(io.BytesIO(file_data))
            full_text = ""
            pages = []
            
            # First extract text from all pages
            for i, page in enumerate(pdf.pages):
                text = page.extract_text(x_tolerance=3, y_tolerance=3)
                if text:
                    # Clean the text
                    text = text.replace('\xa0', ' ')  # Replace non-breaking spaces
                    text = re.sub(r'\s+', ' ', text)  # Normalize whitespace
                    text = text.strip()
                    
                    full_text += f"\n\n=== Page {i+1} ===\n\n" + text
                    pages.append(Document(page_content=text, metadata={"page": i+1}))
            
            pdf.close()
            
            # Create a more effective text splitter for better context preservation
            text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=1000,  # Smaller chunks for better retrieval
                chunk_overlap=200,  # More overlap to preserve context
                separators=["\n\n", "\n", ". ", " ", ""],
                add_start_index=True
            )
            
            # Log the extraction results for debugging
            logging.info(f"Extracted {len(pages)} pages from PDF")
            logging.info(f"Total text length: {len(full_text)} characters")
            
            chunked_documents = text_splitter.split_documents(pages)
            
            for chunk in chunked_documents:
                c.execute("INSERT INTO pdf_chunks (upload_id, chunk_text) VALUES (?, ?)",
                        (upload_id, chunk.page_content))
        except Exception as e:
            logging.error(f"Error processing PDF: {str(e)}")
            flash(f'Error processing PDF: {str(e)}', 'error')
        
        conn.commit()
        conn.close()
        flash('File uploaded successfully', 'success')
    else:
        flash('Only PDF files are allowed', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/view_pdf/<int:file_id>')
def view_pdf(file_id):
    if 'user_id' not in session:
        flash('Please login to view files', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("SELECT file_data, filename FROM uploads WHERE id=? AND user_id=?", (file_id, session['user_id']))
    file_data = c.fetchone()
    conn.close()
    
    if file_data:
        session['current_pdf_id'] = file_id
        response = send_file(
            io.BytesIO(file_data[0]),
            mimetype='application/pdf',
            as_attachment=False,
            download_name=file_data[1]
        )
        return response
    
    flash('File not found or you don\'t have permission to view it', 'error')
    return redirect(url_for('dashboard'))

@app.route('/delete_pdf/<int:file_id>', methods=['POST'])
def delete_pdf(file_id):
    if 'user_id' not in session:
        flash('Please login to delete files', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("DELETE FROM pdf_chunks WHERE upload_id=?", (file_id,))
    c.execute("DELETE FROM uploads WHERE id=? AND user_id=?", (file_id, session['user_id']))
    conn.commit()
    conn.close()
    
    if session.get('current_pdf_id') == file_id:
        session.pop('current_pdf_id', None)
    
    flash('File deleted successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/select_pdf/<int:file_id>', methods=['GET'])
def select_pdf(file_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("SELECT id, filename FROM uploads WHERE id=? AND user_id=?", (file_id, session['user_id']))
    file_data = c.fetchone()
    conn.close()
    
    if file_data:
        session['current_pdf_id'] = file_id
        return jsonify({'success': True, 'filename': file_data[1]})
    
    return jsonify({'error': 'File not found or access denied'}), 403

@app.route('/ask', methods=['POST'])
def ask_question():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if 'current_pdf_id' not in session:
        return jsonify({'error': 'No PDF selected'}), 400
    
    data = request.get_json()
    question = data.get('question', '')
    model_type = data.get('model_type', '')
    model_name = data.get('model_name', '')
    api_key = data.get('api_key', '')
    api_base = data.get('api_base', '')
    
    if not question:
        return jsonify({'error': 'No question provided'}), 400
    
    if not model_type or not model_name:
        return jsonify({'error': 'Model type and name must be provided'}), 400
    
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("SELECT chunk_text FROM pdf_chunks WHERE upload_id=?", (session['current_pdf_id'],))
    chunks = [row[0] for row in c.fetchall()]
    conn.close()
    
    if not chunks:
        return jsonify({'error': 'No content found for the selected PDF'}), 400
    
    logging.info(f"Processing question: {question}")
    logging.info(f"Number of chunks available: {len(chunks)}")
    
    # Create documents with page metadata
    documents = [Document(page_content=chunk) for chunk in chunks]
    
    # Use BM25 for better retrieval of relevant chunks
    retriever = BM25Retriever.from_documents(documents)
    retriever.k = 8  # Retrieve more chunks for better context
    
    # Get relevant documents
    related_documents = retriever.get_relevant_documents(question)
    
    # Log the number of related documents found
    logging.info(f"Retrieved {len(related_documents)} relevant chunks")
    
    # Build context with page numbers if available
    formatted_chunks = []
    for doc in related_documents:
        if "page" in doc.metadata:
            formatted_chunks.append(f"[Page {doc.metadata['page']}] {doc.page_content}")
        else:
            formatted_chunks.append(doc.page_content)
    
    context = "\n\n".join(formatted_chunks)
    
    # Create a more detailed prompt for better answers
    template = """
You are an intelligent assistant specialized in answering questions about documents. You'll be provided with text excerpts from a document and a question about that document.

CONTEXT:
{context}

QUESTION:
{question}

Please follow these guidelines when providing your answer:
1. Answer ONLY based on the provided context. Do not use external knowledge.
2. If the answer can't be found in the context, honestly say "I don't see information about this in the provided document sections."
3. Include relevant page numbers in your answer when possible (e.g., "According to page 3...").
4. Your response should be accurate, thorough, and directly address the question.
5. Use a clear, professional tone.
6. Provide direct quotes from the document when appropriate.

ANSWER:
"""
    prompt = ChatPromptTemplate.from_template(template)
    
    try:
        if model_type == 'groq':
            # Use GROQ_API_KEY from environment
            groq_api_key = os.environ.get('GROQ_API_KEY')
            if not groq_api_key:
                return jsonify({'error': 'Groq API key not found in environment variables'}), 400
            model = ChatGroq(groq_api_key=groq_api_key, model_name=model_name)
        elif model_type == 'ollama':
            model = ChatOllama(model=model_name, base_url=api_base if api_base else "http://localhost:11434")
        else:
            return jsonify({'error': 'Invalid model type'}), 400
        
        chain = prompt | model
        answer = chain.invoke({"question": question, "context": context})
        return jsonify({'answer': answer.content})
    except Exception as e:
        logging.error(f"Error in AI model processing: {str(e)}")
        return jsonify({'error': f'Error processing request: {str(e)}'}), 500

@app.route('/notes')
def notes():
    if 'user_id' not in session:
        flash('Please login to view notes', 'error')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("SELECT id, title, last_edited FROM notes WHERE user_id=? ORDER BY last_edited DESC", (session['user_id'],))
    notes = c.fetchall()
    conn.close()
    
    return render_template('note_editor.html', notes=notes)

@app.route('/note/<int:note_id>')
def get_note(note_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("SELECT title, content_delta, content_html FROM notes WHERE id=? AND user_id=?", 
             (note_id, session['user_id']))
    note = c.fetchone()
    conn.close()
    
    if note:
        return jsonify({
            'title': note[0],
            'content_delta': note[1],
            'content_html': note[2]
        })
    
    return jsonify({'error': 'Note not found or access denied'}), 403

@app.route('/create_note', methods=['POST'])
def create_note():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    title = data.get('title', 'Untitled Note')
    content_delta = data.get('content_delta', '{}')
    content_html = data.get('content_html', '')
    
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("INSERT INTO notes (user_id, title, content_delta, content_html) VALUES (?, ?, ?, ?)",
             (session['user_id'], title, content_delta, content_html))
    note_id = c.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'note_id': note_id})

@app.route('/update_note/<int:note_id>', methods=['POST'])
def update_note(note_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    title = data.get('title')
    content_delta = data.get('content_delta')
    content_html = data.get('content_html')
    
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("UPDATE notes SET title=?, content_delta=?, content_html=?, last_edited=CURRENT_TIMESTAMP WHERE id=? AND user_id=?",
             (title, content_delta, content_html, note_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/delete_note/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute("DELETE FROM notes WHERE id=? AND user_id=?", (note_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(str(e))
    return render_template('500.html'), 500
