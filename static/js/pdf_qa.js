/**
 * PDF Question-Answering Interface
 */

document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const modelTypeSelect = document.getElementById('model-type');
    const groqOptions = document.getElementById('groq-options');
    const ollamaOptions = document.getElementById('ollama-options');
    const ollamaApiBaseInput = document.getElementById('ollama-api-base');
    const groqModelSelect = document.getElementById('groq-model');
    const ollamaModelSelect = document.getElementById('ollama-model');
    const questionInput = document.getElementById('question');
    const askButton = document.getElementById('ask-button');
    const answerContainer = document.getElementById('answer-container');
    const answerText = document.getElementById('answer-text');
    const loadingIndicator = document.getElementById('loading-indicator');
    const aiStatus = document.getElementById('ai-status');
    const pdfQaInterface = document.getElementById('pdf-qa-interface');
    const selectedPdfName = document.getElementById('selected-pdf-name');
    
    // Event listeners for model type selection
    if (modelTypeSelect) {
        modelTypeSelect.addEventListener('change', function() {
            if (this.value === 'groq') {
                groqOptions.style.display = 'block';
                ollamaOptions.style.display = 'none';
            } else {
                groqOptions.style.display = 'none';
                ollamaOptions.style.display = 'block';
            }
        });
    }
    
    // Select PDF buttons
    const selectPdfButtons = document.querySelectorAll('.select-pdf');
    if (selectPdfButtons.length > 0) {
        selectPdfButtons.forEach(button => {
            button.addEventListener('click', function() {
                const fileId = this.getAttribute('data-id');
                selectPdfForQA(fileId);
            });
        });
    }
    
    // Ask Question button
    if (askButton) {
        askButton.addEventListener('click', askQuestionAboutPdf);
    }
    
    // API key is now managed by environment variables
    
    /**
     * Select a PDF for question-answering
     * @param {string} fileId - The ID of the PDF file
     */
    function selectPdfForQA(fileId) {
        fetch(`/select_pdf/${fileId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    aiStatus.style.display = 'none';
                    pdfQaInterface.style.display = 'block';
                    selectedPdfName.textContent = data.filename || 'Selected PDF';
                    showNotification('PDF selected for question-answering', 'success');
                } else {
                    showNotification('Error selecting PDF: ' + (data.error || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('Error selecting PDF:', error);
                showNotification('Error selecting PDF: ' + error.message, 'error');
            });
    }
    
    /**
     * Ask a question about the selected PDF
     */
    function askQuestionAboutPdf() {
        // Get question and model information
        const question = questionInput.value.trim();
        if (!question) {
            showNotification('Please enter a question', 'error');
            return;
        }
        
        const modelType = modelTypeSelect.value;
        let modelName, apiBase;
        
        if (modelType === 'groq') {
            modelName = groqModelSelect.value;
            // API key is managed by environment variables
        } else {
            modelName = ollamaModelSelect.value;
            apiBase = ollamaApiBaseInput.value.trim();
        }
        
        // Prepare request data
        const requestData = {
            question: question,
            model_type: modelType,
            model_name: modelName
        };
        
        if (modelType === 'ollama') {
            requestData.api_base = apiBase;
        }
        
        // Add debug info to the console
        console.log('Sending request with data:', requestData);
        
        // Show loading indicator
        loadingIndicator.style.display = 'block';
        answerContainer.style.display = 'none';
        
        // Send request to API
        fetch('/ask', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        })
        .then(response => {
            // First check if response is ok
            if (!response.ok) {
                // For error responses, check the content-type to handle differently
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    // If JSON error, extract the message
                    return response.json().then(err => {
                        throw new Error(err.error || 'Failed to get answer');
                    });
                } else {
                    // For non-JSON errors (like HTML error pages)
                    throw new Error(`Server error: ${response.status} ${response.statusText}`);
                }
            }
            
            // Check content type to ensure we're getting JSON
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                throw new Error('Received non-JSON response from server');
            }
            
            return response.json();
        })
        .then(data => {
            // Log the response data
            console.log('Received response:', data);
            
            // Display answer
            loadingIndicator.style.display = 'none';
            answerContainer.style.display = 'block';
            
            if (data && data.answer) {
                answerText.innerHTML = data.answer.replace(/\n/g, '<br>');
            } else {
                answerText.innerHTML = 'Received empty or invalid response from the server.';
            }
        })
        .catch(error => {
            loadingIndicator.style.display = 'none';
            console.error('Error asking question:', error);
            showNotification('Error: ' + error.message, 'error');
        });
    }
});
