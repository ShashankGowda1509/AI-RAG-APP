/**
 * Note Editor functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Quill editor
    const quill = new Quill('#editor-container', {
        theme: 'snow',
        modules: {
            toolbar: [
                [{ 'header': [1, 2, 3, 4, 5, 6, false] }],
                ['bold', 'italic', 'underline', 'strike'],
                [{ 'color': [] }, { 'background': [] }],
                [{ 'list': 'ordered'}, { 'list': 'bullet' }],
                [{ 'align': [] }],
                ['link', 'code-block'],
                ['clean']
            ]
        },
        placeholder: 'Start writing your note here...'
    });
    
    // DOM Elements
    const noteTitleInput = document.getElementById('note-title');
    const saveNoteBtn = document.getElementById('save-note-btn');
    const newNoteBtn = document.getElementById('new-note-btn');
    const notesList = document.getElementById('notes-list');
    
    // Current note being edited
    let currentNoteId = null;
    
    // Event Listeners
    if (saveNoteBtn) {
        saveNoteBtn.addEventListener('click', saveNote);
    }
    
    if (newNoteBtn) {
        newNoteBtn.addEventListener('click', createNewNote);
    }
    
    // Add event listeners to note items
    const noteItems = document.querySelectorAll('.note-item');
    if (noteItems.length > 0) {
        noteItems.forEach(item => {
            item.addEventListener('click', function(e) {
                // Don't load the note if the delete button was clicked
                if (e.target.closest('.delete-note-btn')) {
                    return;
                }
                
                const noteId = this.getAttribute('data-id');
                loadNote(noteId);
                e.preventDefault();
            });
        });
    }
    
    // Add event listeners to delete buttons
    const deleteButtons = document.querySelectorAll('.delete-note-btn');
    if (deleteButtons.length > 0) {
        deleteButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                const noteId = this.getAttribute('data-id');
                deleteNote(noteId);
                e.stopPropagation(); // Stop the click from bubbling to the note item
            });
        });
    }
    
    /**
     * Create a new note
     */
    function createNewNote() {
        // Reset the editor
        quill.setContents([]);
        noteTitleInput.value = 'Untitled Note';
        currentNoteId = null;
        
        // Create a new note on the server
        const noteData = {
            title: noteTitleInput.value,
            content_delta: JSON.stringify(quill.getContents()),
            content_html: quill.root.innerHTML
        };
        
        fetch('/create_note', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(noteData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                currentNoteId = data.note_id;
                showNotification('New note created', 'success');
                
                // Add the new note to the list
                addNoteToList(data.note_id, 'Untitled Note', new Date().toISOString());
            } else {
                showNotification('Error creating note: ' + (data.error || 'Unknown error'), 'error');
            }
        })
        .catch(error => {
            console.error('Error creating note:', error);
            showNotification('Error creating note: ' + error.message, 'error');
        });
    }
    
    /**
     * Save the current note
     */
    function saveNote() {
        if (currentNoteId === null) {
            createNewNote();
            return;
        }
        
        const noteData = {
            title: noteTitleInput.value,
            content_delta: JSON.stringify(quill.getContents()),
            content_html: quill.root.innerHTML
        };
        
        fetch(`/update_note/${currentNoteId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(noteData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('Note saved successfully', 'success');
                
                // Update the note title in the list
                const noteItem = document.querySelector(`.note-item[data-id="${currentNoteId}"]`);
                if (noteItem) {
                    const titleElement = noteItem.querySelector('h6');
                    if (titleElement) {
                        titleElement.textContent = noteTitleInput.value;
                    }
                }
            } else {
                showNotification('Error saving note: ' + (data.error || 'Unknown error'), 'error');
            }
        })
        .catch(error => {
            console.error('Error saving note:', error);
            showNotification('Error saving note: ' + error.message, 'error');
        });
    }
    
    /**
     * Load a note for editing
     * @param {string} noteId - The ID of the note to load
     */
    function loadNote(noteId) {
        fetch(`/note/${noteId}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showNotification('Error loading note: ' + data.error, 'error');
                    return;
                }
                
                // Set the current note ID
                currentNoteId = noteId;
                
                // Update the editor
                noteTitleInput.value = data.title;
                
                // Set the content
                if (data.content_delta) {
                    try {
                        const delta = JSON.parse(data.content_delta);
                        quill.setContents(delta);
                    } catch (e) {
                        console.error('Error parsing delta JSON:', e);
                        // Fallback to HTML content
                        quill.root.innerHTML = data.content_html || '';
                    }
                } else {
                    quill.root.innerHTML = data.content_html || '';
                }
                
                // Highlight the selected note
                const noteItems = document.querySelectorAll('.note-item');
                noteItems.forEach(item => {
                    item.classList.remove('active');
                });
                const selectedNote = document.querySelector(`.note-item[data-id="${noteId}"]`);
                if (selectedNote) {
                    selectedNote.classList.add('active');
                }
            })
            .catch(error => {
                console.error('Error loading note:', error);
                showNotification('Error loading note: ' + error.message, 'error');
            });
    }
    
    /**
     * Delete a note
     * @param {string} noteId - The ID of the note to delete
     */
    function deleteNote(noteId) {
        if (!confirm('Are you sure you want to delete this note?')) {
            return;
        }
        
        fetch(`/delete_note/${noteId}`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Remove the note from the list
                const noteItem = document.querySelector(`.note-item[data-id="${noteId}"]`);
                if (noteItem) {
                    noteItem.remove();
                }
                
                // If the deleted note was the current note, create a new one
                if (currentNoteId === noteId) {
                    createNewNote();
                }
                
                showNotification('Note deleted successfully', 'success');
            } else {
                showNotification('Error deleting note: ' + (data.error || 'Unknown error'), 'error');
            }
        })
        .catch(error => {
            console.error('Error deleting note:', error);
            showNotification('Error deleting note: ' + error.message, 'error');
        });
    }
    
    /**
     * Add a new note to the list
     * @param {string} id - The note ID
     * @param {string} title - The note title
     * @param {string} date - The creation date
     */
    function addNoteToList(id, title, date) {
        const formattedDate = new Date(date).toLocaleString();
        
        // Create new note item element
        const noteItem = document.createElement('a');
        noteItem.className = 'list-group-item list-group-item-action note-item d-flex justify-content-between align-items-center active';
        noteItem.href = '#';
        noteItem.setAttribute('data-id', id);
        
        noteItem.innerHTML = `
            <div>
                <h6 class="mb-1">${title}</h6>
                <small class="text-muted">${formattedDate}</small>
            </div>
            <button class="btn btn-sm btn-outline-danger delete-note-btn" data-id="${id}">
                <i class="fas fa-trash"></i>
            </button>
        `;
        
        // Add click event listeners
        noteItem.addEventListener('click', function(e) {
            if (!e.target.closest('.delete-note-btn')) {
                loadNote(id);
                e.preventDefault();
            }
        });
        
        const deleteBtn = noteItem.querySelector('.delete-note-btn');
        deleteBtn.addEventListener('click', function(e) {
            deleteNote(id);
            e.stopPropagation();
        });
        
        // Add to the list
        if (notesList) {
            // If there's a "no notes" message, remove it
            const emptyMessage = notesList.querySelector('.text-center');
            if (emptyMessage) {
                emptyMessage.remove();
            }
            
            // Add the new note at the top of the list
            notesList.insertBefore(noteItem, notesList.firstChild);
        }
    }
    
    // Start with a new note if no notes exist
    if (notesList && notesList.children.length === 0) {
        createNewNote();
    }
});
