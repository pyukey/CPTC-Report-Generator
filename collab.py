#!/usr/bin/env python3
import os
import shutil
import http.server
import socketserver
import urllib.parse
from pathlib import Path

currentFile = ""

class FileBrowserHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global currentFile
        # Parse the URL
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)

        if 'file' in query_params:
            dir_name = query_params['file'][0].split('/')[0]

            # Sanitize dir_name here to prevent path traversal

            if 'template' in query_params and query_params['template'][0].lower() == 'true':
                findings_dir = os.path.join("findings", dir_name)
                if not os.path.exists(findings_dir):
                    os.makedirs(findings_dir)
                    template_dir = os.path.join("templates", dir_name)
                    files_to_copy = ["name.tex", "details.tex", "confirmation.tex",
                                    "impact.tex", "mitigation.tex", "references.tex"]
                    for file in files_to_copy:
                        shutil.copy(os.path.join(template_dir, file), os.path.join(findings_dir, file))

                    lock_files = ["nameLock.txt", "detailLock.txt", "confirmLock.txt",
                                "impactLock.txt", "mitigateLock.txt", "referLock.txt"]
                    for lock_file in lock_files:
                        with open(os.path.join(findings_dir, lock_file), "w") as f:
                            f.write("n")

                filename = os.path.join("findings", query_params['file'][0])
            else:
                filename = os.path.join("findings", query_params['file'][0])

            currentFile = dir_name
            return self.serve_file_content(filename)

        elif 'writable' in query_params and currentFile != '':
            # Use currentFile cautiously (consider thread safety)
            lock_file_path = os.path.join("findings", currentFile, query_params['writable'][0] + "Lock.txt")
            try:
                with open(lock_file_path, "r") as f:
                    content = f.read().strip()
                
                # Send proper HTTP response
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
                return
                
            except FileNotFoundError:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Lock file not found')
                return
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f'Error reading lock file: {str(e)}'.encode('utf-8'))
                return

        elif 'lock' in query_params and currentFile != '':
            # New endpoint to set lock status
            lock_type = query_params['lock'][0]
            lock_status = query_params.get('status', ['y'])[0]  # Default to 'y' (locked)
            
            lock_file_path = os.path.join("findings", currentFile, lock_type + "Lock.txt")
            try:
                with open(lock_file_path, "w") as f:
                    f.write(lock_status)
                
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Lock status updated')
                return
                
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f'Error updating lock: {str(e)}'.encode('utf-8'))
                return

        return self.serve_directory_listing()

    def do_POST(self):
        global currentFile
        # Parse the URL
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        if 'save' in query_params and currentFile != '':
            # New endpoint to save file content
            file_type = query_params['save'][0]
            
            # Read the POST data
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                # Decode the POST data (it should be LaTeX content)
                latex_content = post_data.decode('utf-8')
                
                # Map file types to actual filenames
                file_mapping = {
                    'detail': 'details.tex',
                    'confirm': 'confirmation.tex',
                    'impact': 'impact.tex',
                    'mitigate': 'mitigation.tex',
                    'refer': 'references.tex'
                }
                
                if file_type in file_mapping:
                    file_path = os.path.join("findings", currentFile, file_mapping[file_type])
                    
                    # Write the LaTeX content to the file
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(latex_content)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'File saved successfully')
                    return
                else:
                    self.send_response(400)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'Invalid file type')
                    return
                    
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f'Error saving file: {str(e)}'.encode('utf-8'))
                return
        
        # If no valid POST endpoint found, return 404
        self.send_response(404)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Endpoint not found')

        return self.serve_directory_listing()

    
    def serve_directory_listing(self):
        """Serve an HTML page with clickable file list"""
        current_dir = os.getcwd()
        findings = []
        
        # Get all findings in findings directory
        for item in os.listdir(current_dir+'/findings'):
            findings.append(item)
        
        findings.sort()
        templates = []
        
        # Get all findings in findings directory
        for item in os.listdir(current_dir+'/templates'):
            templates.append(item)
        
        templates.sort()

        scriptContent = r"""
            <script>
                function parseLatexToHtml(latexText) {
                    let html = latexText;
                    
                    html = html.replace(/\\begin\{(itemize)\}/g, '<ul>');
                    html = html.replace(/\\end\{(itemize)\}/g, '</ul>');
                    html = html.replace(/\\begin\{(enumerate)\}/g, '<ol>');
                    html = html.replace(/\\end\{(enumerate)\}/g, '</ol>');
                    html = html.replace(/\\item\{([^\n]*?)(.)$/gm, '<li>$1</li>');

                    html = html.replace(/\\\\/g, '</p><p>');
                    
                    // Convert inline formatting (order matters - do nested ones first)
                    html = html.replace(/\\texttt\{([^{}]*?)\}/g, '<code>$1</code>');
                    html = html.replace(/\\textbf\{([^{}]*?)\}/g, '<strong>$1</strong>');
                    html = html.replace(/\\textit\{([^{}]*?)\}/g, '<em>$1</em>');
                    
                    // Convert paragraph breaks (double newlines) to <p> tags
                    html = html.replace(/\n\s*\n/g, '</p><p>');
                    
                    // Wrap in paragraph tags if there's content
                    if (html.trim()) {
                        html = '<p>' + html + '</p>';
                    }
                    
                    return html;
                }

                function parseHtmlToLatex(htmlText) {
                    let latex = htmlText;
                    
                    // Remove outer div wrappers that might be added
                    latex = latex.replace(/<div class="[^"]*-contents">(.*?)<\/div>/gs, '$1');
                    
                    // Convert lists first (before removing other tags)
                    latex = latex.replace(/<ul>/g, '\\begin{itemize}');
                    latex = latex.replace(/<\/ul>/g, '\\end{itemize}');
                    latex = latex.replace(/<ol>/g, '\\begin{enumerate}');
                    latex = latex.replace(/<\/ol>/g, '\\end{enumerate}');
                    latex = latex.replace(/<li>(.*?)<\/li>/gs, '\\item{$1');
                    
                    // Convert inline formatting
                    latex = latex.replace(/<code[^>]*>(.*?)<\/code>/gs, '\\texttt{$1}');
                    latex = latex.replace(/<strong[^>]*>(.*?)<\/strong>/gs, '\\textbf{$1}');
                    latex = latex.replace(/<b[^>]*>(.*?)<\/b>/gs, '\\textbf{$1}');
                    latex = latex.replace(/<em[^>]*>(.*?)<\/em>/gs, '\\textit{$1}');
                    latex = latex.replace(/<i[^>]*>(.*?)<\/i>/gs, '\\textit{$1}');
                    
                    // Convert <br> tags to LaTeX line breaks
                    latex = latex.replace(/<br\s*\/?>/g, '\\\\');
                    
                    // Handle paragraph tags - convert to double newlines
                    latex = latex.replace(/<\/p>\s*<p[^>]*>/g, '\n\n');
                    latex = latex.replace(/<p[^>]*>/g, '');
                    latex = latex.replace(/<\/p>/g, '');
                    
                    // Remove any remaining HTML tags
                    latex = latex.replace(/<[^>]*>/g, '');
                    
                    // Decode HTML entities
                    latex = latex.replace(/&lt;/g, '<');
                    latex = latex.replace(/&gt;/g, '>');
                    latex = latex.replace(/&amp;/g, '&');
                    latex = latex.replace(/&quot;/g, '"');
                    latex = latex.replace(/&#39;/g, "'");
                    latex = latex.replace(/&nbsp;/g, ' ');
                    
                    // Clean up extra whitespace and newlines
                    latex = latex.replace(/\n\s*\n\s*\n+/g, '\n\n');
                    latex = latex.replace(/^\s+|\s+$/g, ''); // trim start and end
                    
                    console.log('HTML to LaTeX conversion:');
                    console.log('Input HTML:', htmlText);
                    console.log('Output LaTeX:', latex);
                    
                    return latex;
                }
    
                function loadFile(filename, isTemplate) {
                    fetch('/?file=' + encodeURIComponent(filename+'/name.tex') + '&template=' + isTemplate)
                        .then(response => response.text())
                        .then(data => {
                            document.getElementById('finding-name').innerHTML = parseLatexToHtml(data);
                        })
                        .catch(error => {
                            document.getElementById('finding-name').innerHTML = 'Error loading file: ' + error;
                        });
                    fetch('/?file=' + encodeURIComponent(filename+'/details.tex') + '&template=' + isTemplate)
                        .then(response => response.text())
                        .then(data => {
                            document.getElementById('detail-editor').innerHTML = parseLatexToHtml(data);
                        })
                        .catch(error => {
                            document.getElementById('detail-editor').innerHTML = 
                                '<p style="color: red;">Error loading file: ' + error + '</p>';
                        });
                    fetch('/?file=' + encodeURIComponent(filename+'/confirmation.tex') + '&template=' + isTemplate)
                        .then(response => response.text())
                        .then(data => {
                            document.getElementById('confirm-editor').innerHTML = 
                                '<div class="confirm-contents">' + parseLatexToHtml(data) + '</div>';
                        })
                        .catch(error => {
                            document.getElementById('confirm-editor').innerHTML = 
                                '<p style="color: red;">Error loading file: ' + error + '</p>';
                        });
                    fetch('/?file=' + encodeURIComponent(filename+'/impact.tex') + '&template=' + isTemplate)
                        .then(response => response.text())
                        .then(data => {
                            document.getElementById('impact-editor').innerHTML = 
                                '<div class="impact-contents">' + parseLatexToHtml(data) + '</div>';
                        })
                        .catch(error => {
                            document.getElementById('impact-editor').innerHTML = 
                                '<p style="color: red;">Error loading file: ' + error + '</p>';
                        });
                    fetch('/?file=' + encodeURIComponent(filename+'/mitigation.tex') + '&template=' + isTemplate)
                        .then(response => response.text())
                        .then(data => {
                            document.getElementById('mitigate-editor').innerHTML = 
                                '<div class="mitigate-contents">' + parseLatexToHtml(data) + '</div>';
                        })
                        .catch(error => {
                            document.getElementById('mitigate-editor').innerHTML = 
                                '<p style="color: red;">Error loading file: ' + error + '</p>';
                        });
                    fetch('/?file=' + encodeURIComponent(filename+'/references.tex') + '&template=' + isTemplate)
                        .then(response => response.text())
                        .then(data => {
                            document.getElementById('refer-editor').innerHTML = 
                                '<div class="refer-contents">' + parseLatexToHtml(data) + '</div>';
                        })
                        .catch(error => {
                            document.getElementById('refer-editor').innerHTML = 
                                '<p style="color: red;">Error loading file: ' + error + '</p>';
                        });
                    if (document.getElementById('finding-'+filename) == null) {
                        document.getElementById('finding-list').innerHTML += '<li id="finding-' + filename + '" class="finding-item">' + '<a href="\#" onclick="return loadFile(\'' + filename + '\', false)">' + filename + '</a>' + '</li>';
                        document.getElementById('finding-count').textContent = parseInt(document.getElementById('finding-count').textContent) + 1;
                    }
                    
                    // Reset all editors to view mode and check their lock status
                    Object.keys(editors).forEach(type => {
                        const editorObj = editors[type];
                        editorObj.isEditable = false;
                        editorObj.editor.contentEditable = false;
                        editorObj.toggle.textContent = 'Edit';
                        editorObj.toggle.classList.remove('editing');
                        editorObj.editor.classList.add('read-only');
                        enableToolbarButtons(false, type);
                    });
                    
                    return false; // Prevent default link behavior
                }
                
                function escapeHtml(text) {
                    var div = document.createElement('div');
                    div.textContent = text;
                    return div.innerHTML;
                }
                
                // Global editors object - will be populated when DOM loads
                let editors = {};

                // Toggle edit mode with improved locking and file saving
                function toggleEdit(type) {
                    const editorObj = editors[type];
                    if (!editorObj || !editorObj.editor || !editorObj.toggle) {
                        console.error('Editor object not found for type:', type);
                        return;
                    }
                    
                    // If currently in edit mode, switch to view mode and save
                    if (editorObj.isEditable) {
                        // Get current content and convert to LaTeX
                        const htmlContent = editorObj.editor.innerHTML;
                        console.log('Attempting to save content for type:', type);
                        console.log('Current HTML content:', htmlContent);
                        
                        const latexContent = parseHtmlToLatex(htmlContent);
                        console.log('Converted LaTeX content:', latexContent);
                        
                        // Save the content to the file
                        console.log('Making POST request to save file...');
                        fetch('/?save=' + type, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'text/plain; charset=utf-8',
                            },
                            body: latexContent
                        })
                        .then(response => {
                            console.log('Save response status:', response.status);
                            if (!response.ok) {
                                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                            }
                            return response.text();
                        })
                        .then(data => {
                            console.log('File saved successfully:', data);
                            // Release the lock after successful save
                            return fetch('/?lock=' + type + '&status=n');
                        })
                        .then(response => {
                            if (response.ok) {
                                console.log('Lock released successfully');
                                editorObj.isEditable = false;
                                editorObj.editor.contentEditable = false;
                                editorObj.toggle.textContent = 'Edit';
                                editorObj.toggle.classList.remove('editing');
                                editorObj.toggle.title = 'Switch to Edit Mode';
                                editorObj.editor.classList.add('read-only');
                                enableToolbarButtons(false, type);
                                // Clear selection when switching to view mode
                                if (window.getSelection) {
                                    window.getSelection().removeAllRanges();
                                }
                                
                                // Show a brief save confirmation
                                showSaveConfirmation(type);
                            }
                        })
                        .catch(error => {
                            console.error('Error saving file or releasing lock:', error);
                            alert('Error saving changes: ' + error.message + '. Your changes may not be saved.');
                            // Still switch to view mode even if save failed
                            editorObj.isEditable = false;
                            editorObj.editor.contentEditable = false;
                            editorObj.toggle.textContent = 'Edit';
                            editorObj.toggle.classList.remove('editing');
                            editorObj.toggle.title = 'Switch to Edit Mode';
                            editorObj.editor.classList.add('read-only');
                            enableToolbarButtons(false, type);
                        });
                    } else {
                        // Check if we can acquire the lock
                        fetch('/?writable=' + type)
                            .then(response => {
                                if (!response.ok) {
                                    throw new Error('Lock file not found');
                                }
                                return response.text();
                            })
                            .then(data => {
                                const lockStatus = data.trim().toLowerCase();
                                if (lockStatus === 'n') {
                                    // Lock is available, acquire it
                                    return fetch('/?lock=' + type + '&status=y');
                                } else {
                                    // Lock is taken
                                    alert('This section is currently being edited by another user. Please try again later.');
                                    throw new Error('Section locked');
                                }
                            })
                            .then(response => {
                                if (response.ok) {
                                    // Successfully acquired lock, switch to edit mode
                                    editorObj.isEditable = true;
                                    editorObj.editor.contentEditable = true;
                                    editorObj.toggle.textContent = 'View';
                                    editorObj.toggle.classList.add('editing');
                                    editorObj.toggle.title = 'Switch to View Mode (will save changes)';
                                    editorObj.editor.classList.remove('read-only');
                                    enableToolbarButtons(true, type);
                                    updateToolbarState(type);
                                }
                            })
                            .catch(error => {
                                if (error.message !== 'Section locked') {
                                    console.error('Error with locking system:', error);
                                    // Fallback: allow editing anyway
                                    editorObj.isEditable = true;
                                    editorObj.editor.contentEditable = true;
                                    editorObj.toggle.textContent = 'View';
                                    editorObj.toggle.classList.add('editing');
                                    editorObj.toggle.title = 'Switch to View Mode (will save changes)';
                                    editorObj.editor.classList.remove('read-only');
                                    enableToolbarButtons(true, type);
                                    updateToolbarState(type);
                                }
                            });
                    }
                }

                // Show save confirmation
                function showSaveConfirmation(type) {
                    const editorObj = editors[type];
                    const originalText = editorObj.toggle.textContent;
                    
                    // Briefly show "Saved!" on the button
                    editorObj.toggle.textContent = 'Saved!';
                    editorObj.toggle.style.backgroundColor = '#28a745';
                    editorObj.toggle.style.color = 'white';
                    
                    setTimeout(() => {
                        editorObj.toggle.textContent = originalText;
                        editorObj.toggle.style.backgroundColor = '';
                        editorObj.toggle.style.color = '';
                    }, 1500);
                }

                // Enable/disable toolbar buttons for specific editor
                function enableToolbarButtons(enable, type) {
                    // Target toolbar buttons for this specific editor
                    const toolbar = document.querySelector(`[data-editor="${type}"] .toolbar`);
                    if (toolbar) {
                        const toolbarButtons = toolbar.querySelectorAll('button:not(.edit-toggle)');
                        toolbarButtons.forEach(button => {
                            button.disabled = !enable;
                        });
                    } else {
                        console.warn('Toolbar not found for type:', type);
                    }
                }

                // Toggle code formatting
                function toggleCodeFormat(type) {
                    const editorObj = editors[type];
                    if (!editorObj || !editorObj.editor) return;
                    
                    const selection = window.getSelection();
                    
                    if (selection.rangeCount === 0) return;
                    
                    const range = selection.getRangeAt(0);
                    const selectedText = range.toString();
                    
                    if (selectedText) {
                        // Check if already wrapped in code tags
                        const parentElement = range.commonAncestorContainer.parentElement;
                        if (parentElement && parentElement.tagName === 'CODE') {
                            // Remove code formatting
                            const textNode = document.createTextNode(parentElement.textContent);
                            parentElement.parentNode.replaceChild(textNode, parentElement);
                        } else {
                            // Add code formatting
                            const codeElement = document.createElement('code');
                            codeElement.style.backgroundColor = '\#f5f5f5';
                            codeElement.style.padding = '2px 4px';
                            codeElement.style.borderRadius = '3px';
                            codeElement.style.fontFamily = 'monospace';
                            
                            try {
                                range.surroundContents(codeElement);
                            } catch (e) {
                                // Fallback for complex selections
                                codeElement.textContent = selectedText;
                                range.deleteContents();
                                range.insertNode(codeElement);
                            }
                        }
                        
                        selection.removeAllRanges();
                    }
                }

                // Format text with the given command
                function formatText(command, type) {
                    const editorObj = editors[type];
                    if (!editorObj || !editorObj.isEditable || !editorObj.editor) return;
                    
                    // Focus the correct editor first
                    editorObj.editor.focus();
                    
                    if (command === 'code') {
                        toggleCodeFormat(type);
                    } else {
                        document.execCommand(command, false, null);
                    }
                    
                    updateToolbarState(type);
                }

                // Clear all formatting
                function clearFormatting(type) {
                    const editorObj = editors[type];
                    if (!editorObj || !editorObj.isEditable || !editorObj.editor) return;
                    
                    editorObj.editor.focus();
                    document.execCommand('removeFormat', false, null);
                    updateToolbarState(type);
                }

                // Update toolbar button states based on current selection
                function updateToolbarState(type) {
                    const editorObj = editors[type];
                    if (!editorObj || !editorObj.editor) return;
                    
                    // Get toolbar for this specific editor
                    const toolbar = document.querySelector(`[data-editor="${type}"] .toolbar`);
                    if (!toolbar) return;
                    
                    const buttons = toolbar.querySelectorAll('button:not(.edit-toggle)');
                    
                    if (!editorObj.isEditable) {
                        // Clear all active states in view mode
                        buttons.forEach(button => button.classList.remove('active'));
                        return;
                    }

                    buttons.forEach(button => button.classList.remove('active'));

                    // Check which formatting is active
                    if (document.queryCommandState('bold')) {
                        const boldButton = toolbar.querySelector('button[onclick*="bold"]');
                        if (boldButton) boldButton.classList.add('active');
                    }
                    if (document.queryCommandState('italic')) {
                        const italicButton = toolbar.querySelector('button[onclick*="italic"]');
                        if (italicButton) italicButton.classList.add('active');
                    }
                    
                    // Check for code formatting
                    const selection = window.getSelection();
                    if (selection.rangeCount > 0) {
                        const range = selection.getRangeAt(0);
                        const parentElement = range.commonAncestorContainer.parentElement;
                        if (parentElement && parentElement.tagName === 'CODE') {
                            const codeButton = toolbar.querySelector('button[onclick*="code"]');
                            if (codeButton) codeButton.classList.add('active');
                        }
                    }
                }

                // Initialize all editors
                function initializeEditors() {
                    // Initialize editors object with DOM elements
                    editors = {
                        detail: {
                            editor: document.getElementById('detail-editor'),
                            toggle: document.getElementById('detail-toggle'),
                            isEditable: false
                        },
                        confirm: {
                            editor: document.getElementById('confirm-editor'),
                            toggle: document.getElementById('confirm-toggle'),
                            isEditable: false
                        },
                        impact: {
                            editor: document.getElementById('impact-editor'),
                            toggle: document.getElementById('impact-toggle'),
                            isEditable: false
                        },
                        mitigate: {
                            editor: document.getElementById('mitigate-editor'),
                            toggle: document.getElementById('mitigate-toggle'),
                            isEditable: false
                        },
                        refer: {
                            editor: document.getElementById('refer-editor'),
                            toggle: document.getElementById('refer-toggle'),
                            isEditable: false
                        }
                    };

                    Object.keys(editors).forEach(type => {
                        const editorObj = editors[type];
                        
                        if (!editorObj.editor || !editorObj.toggle) {
                            console.error(`Failed to find editor elements for ${type}`);
                            return;
                        }
                        
                        // Add event listeners to each editor
                        editorObj.editor.addEventListener('keyup', () => updateToolbarState(type));
                        editorObj.editor.addEventListener('mouseup', () => updateToolbarState(type));
                        editorObj.editor.addEventListener('focus', () => updateToolbarState(type));
                        
                        // Keyboard shortcuts for each editor
                        editorObj.editor.addEventListener('keydown', function(e) {
                            if (!editorObj.isEditable) return;
                            
                            if (e.ctrlKey || e.metaKey) {
                                switch(e.key) {
                                    case 'b':
                                        e.preventDefault();
                                        formatText('bold', type);
                                        break;
                                    case 'i':
                                        e.preventDefault();
                                        formatText('italic', type);
                                        break;
                                    case 'e':
                                        e.preventDefault();
                                        toggleEdit(type);
                                        break;
                                }
                            }
                        });
                        
                        // Initialize in view mode
                        editorObj.toggle.textContent = 'Edit';
                        editorObj.editor.contentEditable = false;
                        editorObj.editor.classList.add('read-only');
                        enableToolbarButtons(false, type);
                        
                        // Add auto-save on focus loss (as backup)
                        editorObj.editor.addEventListener('blur', function() {
                            if (editorObj.isEditable) {
                                // Auto-save when user clicks outside the editor
                                const htmlContent = editorObj.editor.innerHTML;
                                const latexContent = parseHtmlToLatex(htmlContent);
                                
                                fetch('/?save=' + type, {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'text/plain; charset=utf-8',
                                    },
                                    body: latexContent
                                })
                                .then(response => {
                                    if (response.ok) {
                                        console.log('Auto-saved', type);
                                    }
                                })
                                .catch(error => {
                                    console.warn('Auto-save failed for', type, ':', error);
                                });
                            }
                        });
                    });
                }

                // Initialize everything when DOM is loaded
                document.addEventListener('DOMContentLoaded', function() {
                    console.log('DOM loaded, initializing editors...');
                    initializeEditors();
                });
                
            </script>
        """

        # Generate HTML - fix the button IDs
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CPTC Report Generator</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; }}
                .finding-list, .template-list {{ list-style-type: none; padding: 0; }}
                .finding-item, .template-item {{ 
                    margin: 10px 0; 
                    padding: 10px; 
                    background: #f5f5f5; 
                    border-radius: 5px;
                    border-left: 4px solid #007acc;
                }}
                .finding-item a, .template-item a {{ 
                    text-decoration: none; 
                    color: #007acc; 
                    font-weight: bold;
                }}
                .finding-item a:hover, .template-item a:hover {{ color: #005a9e; }}
                .content-area {{
                    margin-top: 30px;
                    padding: 20px;
                    background: #fff;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    min-height: 200px;
                }}
                .finding-content, .template-content {{
                    white-space: pre-wrap;
                    font-family: 'Courier New', monospace;
                    background: #f9f9f9;
                    padding: 15px;
                    border-radius: 3px;
                    max-height: 500px;
                    overflow-y: auto;
                }}
                .editor-container {{
                    border: 1px solid #ccc;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    margin-bottom: 20px;
                }}
                .toolbar {{
                    display: flex;
                    padding: 10px;
                    background-color: #f5f5f5;
                    border-bottom: 1px solid #ddd;
                    border-radius: 8px 8px 0 0;
                    gap: 5px;
                }}
                .toolbar button {{
                    padding: 8px 12px;
                    border: 1px solid #ddd;
                    background: white;
                    cursor: pointer;
                    border-radius: 4px;
                    font-weight: bold;
                    transition: background-color 0.2s;
                }}
                .toolbar button:hover {{
                    background-color: #e9e9e9;
                }}
                .toolbar button.active {{
                    background-color: #007cba;
                    color: white;
                }}
                .edit-toggle {{
                    margin-right: 10px;
                    font-weight: normal !important;
                }}
                .edit-toggle.editing {{
                    background-color: #28a745 !important;
                    color: white;
                }}
                .separator {{
                    width: 1px;
                    height: 30px;
                    background-color: #ddd;
                    margin: 0 10px;
                }}
                .toolbar button:disabled {{
                    opacity: 0.5;
                    cursor: not-allowed;
                    background-color: #f5f5f5;
                }}
                .editor {{
                    min-height: 100px;
                    padding: 15px;
                    outline: none;
                    line-height: 1.6;
                    font-size: 14px;
                }}
                .editor.read-only {{
                    background-color: #f9f9f9;
                    cursor: default;
                }}
                .editor.read-only:focus {{
                    box-shadow: none;
                }}
                .editor ul, .editor ol {{
                    margin: 10px 0;
                    padding-left: 30px;
                }}
                .editor li {{
                    margin: 5px 0;
                }}
                .editor p {{
                    margin: 10px 0;
                }}
                code {{
                    background-color: #f5f5f5;
                    padding: 2px 4px;
                    border-radius: 3px;
                    font-family: monospace;
                    font-size: 0.9em;
                }}
            </style>
        </head>
        <body>
            <h1>CPTC Report Generator</h1>
            
            <h2>Findings (<span id="finding-count">{len(findings)}</span> total):</h2>
            <ul id="finding-list" class="finding-list">
        """
        
        for filename in findings:
            html += f'''
                <li id="finding-{filename}" class="finding-item">
                    <a href="#" onclick="return loadFile('{filename}', false)">{filename}</a>
                </li>
            '''
        
        html += f"""
            </ul>
            <h2>Templates ({len(templates)} total):</h2>
            <ul class="template-list">
        """
        
        for filename in templates:
            html += f'''
                <li id="template-{filename}" class="template-item">
                    <a href="#" onclick="return loadFile('{filename}', true)">{filename}</a>
                </li>
            '''
        
        html += f"""
            </ul>
            
            
            <div class="content-area">
                <h1 id="finding-name">Name of finding</h1>
                <h2>Details</h2>
                <div data-editor="detail" class="editor-container">
                    <div class="toolbar">
                        <button id="detail-toggle" onclick="toggleEdit('detail')" class="edit-toggle">Edit</button>
                        <button onclick="formatText('bold', 'detail')">B</button>
                        <button onclick="formatText('italic', 'detail')">I</button>
                        <button onclick="formatText('code', 'detail')" title="Code Block">C</button>
                        <button onclick="formatText('insertUnorderedList', 'detail')" title="Bullet List">- List</button>
                        <button onclick="formatText('insertOrderedList', 'detail')" title="Numbered List">1. List</button>
                    </div>
                    <div id="detail-editor" class="editor" contenteditable="false">
                        <p>Click on any file above to view its contents here.</p>
                    </div>
                </div>
                <h2>Confirmation</h2>
                <div data-editor="confirm" class="editor-container">
                    <div class="toolbar">
                        <button id="confirm-toggle" onclick="toggleEdit('confirm')" class="edit-toggle">Edit</button>
                        <button onclick="formatText('bold', 'confirm')">B</button>
                        <button onclick="formatText('italic', 'confirm')">I</button>
                        <button onclick="formatText('code', 'confirm')" title="Code Block">C</button>
                        <button onclick="formatText('insertUnorderedList', 'confirm')" title="Bullet List">- List</button>
                        <button onclick="formatText('insertOrderedList', 'confirm')" title="Numbered List">1. List</button>
                    </div>
                    <div id="confirm-editor" class="editor" contenteditable="false">
                        <p>Click on any file above to view its contents here.</p>
                    </div>
                </div>
                <h2>Impact</h2>
                <div data-editor="impact" class="editor-container">
                    <div class="toolbar">
                        <button id="impact-toggle" onclick="toggleEdit('impact')" class="edit-toggle">Edit</button>
                        <button onclick="formatText('bold', 'impact')">B</button>
                        <button onclick="formatText('italic', 'impact')">I</button>
                        <button onclick="formatText('code', 'impact')" title="Code Block">C</button>
                        <button onclick="formatText('insertUnorderedList', 'impact')" title="Bullet List">- List</button>
                        <button onclick="formatText('insertOrderedList', 'impact')" title="Numbered List">1. List</button>
                    </div>
                    <div id="impact-editor" class="editor" contenteditable="false">
                        <p>Click on any file above to view its contents here.</p>
                    </div>
                </div>
                <h2>Mitigation</h2>
                <div data-editor="mitigate" class="editor-container">
                    <div class="toolbar">
                        <button id="mitigate-toggle" onclick="toggleEdit('mitigate')" class="edit-toggle">Edit</button>
                        <button onclick="formatText('bold', 'mitigate')">B</button>
                        <button onclick="formatText('italic', 'mitigate')">I</button>
                        <button onclick="formatText('code', 'mitigate')" title="Code Block">C</button>
                        <button onclick="formatText('insertUnorderedList', 'mitigate')" title="Bullet List">- List</button>
                        <button onclick="formatText('insertOrderedList', 'mitigate')" title="Numbered List">1. List</button>
                    </div>
                    <div id="mitigate-editor" class="editor" contenteditable="false">
                        <p>Click on any file above to view its contents here.</p>
                    </div>
                </div>
                <h2>References</h2>
                <div data-editor="refer" class="editor-container">
                    <div class="toolbar">
                        <button id="refer-toggle" onclick="toggleEdit('refer')" class="edit-toggle">Edit</button>
                        <button onclick="formatText('bold', 'refer')">B</button>
                        <button onclick="formatText('italic', 'refer')">I</button>
                        <button onclick="formatText('code', 'refer')" title="Code Block">C</button>
                        <button onclick="formatText('insertUnorderedList', 'refer')" title="Bullet List">- List</button>
                        <button onclick="formatText('insertOrderedList', 'refer')" title="Numbered List">1. List</button>
                    </div>
                    <div id="refer-editor" class="editor" contenteditable="false">
                        <p>Click on any file above to view its contents here.</p>
                    </div>
                </div>
            </div>
            {scriptContent}
        </body>
        </html>
        """
        
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def serve_file_content(self, filename):
        """Serve the raw content of a specific file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
            
        except FileNotFoundError:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'File not found')
        except UnicodeDecodeError:
            self.send_response(400)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Cannot read file: not a text file')
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(f'Error reading file: {str(e)}'.encode('utf-8'))

def main():
    PORT = 8000
    
    with socketserver.TCPServer(("", PORT), FileBrowserHandler) as httpd:
        print(f"Server starting on http://localhost:{PORT}")
        print("Press Ctrl+C to stop the server")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped")

if __name__ == "__main__":
    main()