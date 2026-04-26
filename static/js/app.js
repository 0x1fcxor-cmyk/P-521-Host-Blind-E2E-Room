// P-521 Web UI - Frontend JavaScript

const socket = io();
let currentRoomId = null;
let currentUserId = null;
let currentTheme = localStorage.getItem('theme') || 'light';
let savedRooms = JSON.parse(localStorage.getItem('savedRooms') || '[]');
let messageHistory = [];
let selfDestructEnabled = false;
let selfDestructTime = 30;
let sessionStartTime = Date.now();
let messagesSent = 0;
let activityLog = JSON.parse(localStorage.getItem('activityLog') || '[]');
let soundEnabled = localStorage.getItem('soundEnabled') !== 'false';
let replyingTo = null;

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    checkAutoLogin();
    setupSocketListeners();
    applyTheme();
    setupKeyboardShortcuts();
    setupDragAndDrop();
    updateDashboardStats();
    setInterval(updateDashboardStats, 60000); // Update every minute
    loadActivityLog();
    loadMessageHistory();
});

async function checkAutoLogin() {
    try {
        const response = await fetch('/api/auto-login');
        const data = await response.json();
        
        if (data.success && data.auto_logged_in) {
            // Auto-login successful
            sessionStorage.setItem('password', AUTO_PASSWORD);
            
            document.getElementById('loginScreen').classList.add('hidden');
            document.getElementById('mainApp').classList.remove('hidden');
            document.getElementById('currentUser').textContent = data.display_name;
            document.getElementById('settingsDisplayName').value = data.display_name;
            document.getElementById('identityFingerprint').textContent = data.fingerprint;
            document.getElementById('yourFingerprint').textContent = data.fingerprint.substring(0, 16) + '...';
            
            showToast('Auto-logged in from CLI!', 'success');
            
            // Auto-join room if invite link provided
            if (data.invite_link) {
                document.getElementById('inviteLink').value = data.invite_link;
                await joinRoom();
            }
            
            return;
        }
    } catch (error) {
        // Auto-login not available, proceed normally
    }
    
    // Fall back to normal identity check
    checkIdentityStatus();
}

// Socket.io listeners
function setupSocketListeners() {
    socket.on('connect', () => {
        console.log('Connected to server');
    });

    socket.on('joined', (data) => {
        console.log('Joined room:', data.room_id);
    });

    socket.on('message', (data) => {
        displayMessage(data);
    });
}

// Identity Management
async function checkIdentityStatus() {
    try {
        const response = await fetch('/api/identity/status');
        const data = await response.json();
        
        if (data.exists) {
            showLoginForm();
        } else {
            showNewIdentityForm();
        }
    } catch (error) {
        showToast('Error checking identity status', 'danger');
    }
}

function showNewIdentityForm() {
    document.getElementById('newIdentityForm').classList.remove('hidden');
    document.getElementById('loginForm').classList.add('hidden');
}

function showLoginForm() {
    document.getElementById('newIdentityForm').classList.add('hidden');
    document.getElementById('loginForm').classList.remove('hidden');
}

async function createIdentity() {
    const displayName = document.getElementById('displayName').value;
    const password = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (!displayName || !password) {
        showToast('Please fill in all fields', 'warning');
        return;
    }

    if (password !== confirmPassword) {
        showToast('Passwords do not match', 'warning');
        return;
    }

    if (password.length < 8) {
        showToast('Password must be at least 8 characters', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/identity/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password, display_name: displayName })
        });

        const data = await response.json();

        if (data.success) {
            showToast('Identity created successfully!', 'success');
            // Auto-login after creation
            await loginWithPassword(password);
        } else {
            showToast(data.error || 'Failed to create identity', 'danger');
        }
    } catch (error) {
        showToast('Error creating identity', 'danger');
    }
}

async function login() {
    const password = document.getElementById('loginPassword').value;
    await loginWithPassword(password);
}

async function loginWithPassword(password) {
    try {
        const response = await fetch('/api/identity/load', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });

        const data = await response.json();

        if (data.success) {
            // Store password in session for crypto operations
            sessionStorage.setItem('password', password);
            
            document.getElementById('loginScreen').classList.add('hidden');
            document.getElementById('mainApp').classList.remove('hidden');
            document.getElementById('currentUser').textContent = data.display_name;
            document.getElementById('settingsDisplayName').value = data.display_name;
            document.getElementById('identityFingerprint').textContent = data.fingerprint;
            document.getElementById('yourFingerprint').textContent = data.fingerprint.substring(0, 16) + '...';
            showToast('Logged in successfully!', 'success');
        } else {
            showToast(data.error || 'Login failed', 'danger');
        }
    } catch (error) {
        showToast('Error logging in', 'danger');
    }
}

function logout() {
    if (currentRoomId) {
        leaveRoom();
    }
    document.getElementById('mainApp').classList.add('hidden');
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('loginPassword').value = '';
    showToast('Logged out', 'info');
}

// Tab Navigation
function showTab(tabName) {
    // Hide all tabs
    document.getElementById('dashboardTab').classList.add('hidden');
    document.getElementById('joinTab').classList.add('hidden');
    document.getElementById('hostTab').classList.add('hidden');
    document.getElementById('roomsTab').classList.add('hidden');
    document.getElementById('trustTab').classList.add('hidden');
    document.getElementById('settingsTab').classList.add('hidden');
    document.getElementById('helpTab').classList.add('hidden');
    document.getElementById('chatRoom').classList.add('hidden');

    // Remove active class from all nav links
    document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));

    // Show selected tab
    document.getElementById(tabName + 'Tab').classList.remove('hidden');

    // Add active class to clicked link
    event.target.classList.add('active');

    // Load room list if showing rooms tab
    if (tabName === 'rooms') {
        loadRoomList();
    }

    // Load trust info if showing trust tab
    if (tabName === 'trust') {
        loadTrustInfo();
    }

    // Update dashboard if showing dashboard tab
    if (tabName === 'dashboard') {
        updateDashboardStats();
    }

    // Update settings toggles if showing settings tab
    if (tabName === 'settings') {
        document.getElementById('soundToggle').checked = soundEnabled;
        document.getElementById('themeToggle').checked = currentTheme === 'dark';
    }
}

// Room Management
async function joinRoom() {
    const inviteLink = document.getElementById('inviteLink').value;

    if (!inviteLink) {
        showToast('Please enter an invite link', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/room/join', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ invite_link: inviteLink })
        });

        const data = await response.json();

        if (data.success) {
            currentRoomId = data.room_id;
            document.getElementById('roomTitle').textContent = `Room: ${data.room_id_display}`;
            document.getElementById('joinTab').classList.add('hidden');
            document.getElementById('chatRoom').classList.remove('hidden');
            
            // Save room to local storage
            saveRoom(data.room_id_display, inviteLink);
            
            // Join socket room
            socket.emit('join_room', { room_id: currentRoomId });
            
            // Log activity
            addActivity('join', `Joined room ${data.room_id_display}`);
            
            showToast('Joined room successfully!', 'success');
        } else {
            showToast(data.error || 'Failed to join room', 'danger');
        }
    } catch (error) {
        showToast('Error joining room', 'danger');
    }
}

function saveRoom(roomId, inviteLink) {
    const existingIndex = savedRooms.findIndex(r => r.id === roomId);
    if (existingIndex === -1) {
        savedRooms.push({
            id: roomId,
            inviteLink: inviteLink,
            joinedAt: new Date().toISOString()
        });
        localStorage.setItem('savedRooms', JSON.stringify(savedRooms));
    }
}

function loadRoomList() {
    const roomList = document.getElementById('roomList');
    if (savedRooms.length === 0) {
        roomList.innerHTML = `
            <div class="text-center text-muted py-5">
                <i class="bi bi-chat-dots feature-icon"></i>
                <p>No rooms yet. Join a room to get started!</p>
            </div>
        `;
        return;
    }

    roomList.innerHTML = savedRooms.map(room => {
        const joinedDate = new Date(room.joinedAt);
        const timeAgo = getTimeAgo(joinedDate);
        
        return `
            <div class="room-item" onclick="rejoinRoom('${room.id}')">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <div class="fw-bold mb-1">
                            <i class="bi bi-door-open me-2"></i>${room.id}
                        </div>
                        <small class="text-muted">
                            <i class="bi bi-clock me-1"></i>Joined ${timeAgo}
                        </small>
                    </div>
                    <div class="dropdown">
                        <button class="btn btn-sm btn-link text-muted" data-bs-toggle="dropdown">
                            <i class="bi bi-three-dots-vertical"></i>
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="event.stopPropagation(); copyRoomLink('${room.inviteLink}')">
                                <i class="bi bi-clipboard me-2"></i>Copy Link
                            </a></li>
                            <li><a class="dropdown-item text-danger" href="#" onclick="event.stopPropagation(); deleteRoom('${room.id}')">
                                <i class="bi bi-trash me-2"></i>Delete
                            </a></li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function getTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
    return date.toLocaleDateString();
}

function copyRoomLink(inviteLink) {
    navigator.clipboard.writeText(inviteLink).then(() => {
        showToast('Room link copied!', 'success');
    }).catch(() => {
        showToast('Failed to copy link', 'danger');
    });
}

function deleteRoom(roomId) {
    if (confirm('Are you sure you want to delete this room from your list?')) {
        savedRooms = savedRooms.filter(r => r.id !== roomId);
        localStorage.setItem('savedRooms', JSON.stringify(savedRooms));
        loadRoomList();
        showToast('Room deleted', 'info');
    }
}

async function rejoinRoom(roomId) {
    const room = savedRooms.find(r => r.id === roomId);
    if (room) {
        document.getElementById('inviteLink').value = room.inviteLink;
        await joinRoom();
    }
}

function loadTrustInfo() {
    const fingerprint = document.getElementById('identityFingerprint')?.textContent || '';
    document.getElementById('trustFingerprint').textContent = fingerprint;
    loadTrustedContacts();
}

async function loadTrustedContacts() {
    try {
        const response = await fetch('/api/trust/contacts');
        const data = await response.json();
        
        const contactsDiv = document.getElementById('trustedContacts');
        
        if (data.success && data.contacts.length > 0) {
            contactsDiv.innerHTML = data.contacts.map(contact => `
                <div class="participant-item">
                    <div class="participant-avatar">${contact.name.charAt(0).toUpperCase()}</div>
                    <div>
                        <div class="fw-bold">${contact.name}</div>
                        <small class="text-muted">${contact.fingerprint.substring(0, 16)}...</small>
                    </div>
                </div>
            `).join('');
        } else {
            contactsDiv.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="bi bi-person-check feature-icon"></i>
                    <p>No trusted contacts yet.</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading trusted contacts:', error);
    }
}

async function exportIdentity() {
    try {
        const response = await fetch('/api/identity/export');
        const data = await response.json();
        
        if (data.success) {
            const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `p521_identity_${data.data.fingerprint.substring(0, 8)}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Identity exported successfully!', 'success');
        } else {
            showToast(data.error || 'Failed to export identity', 'danger');
        }
    } catch (error) {
        showToast('Error exporting identity', 'danger');
    }
}

async function importIdentity() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        try {
            const content = await file.text();
            const identityData = JSON.parse(content);
            
            const response = await fetch('/api/identity/import', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data: identityData })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('Identity imported successfully!', 'success');
                loadTrustInfo();
            } else {
                showToast(data.error || 'Failed to import identity', 'danger');
            }
        } catch (error) {
            showToast('Error importing identity', 'danger');
        }
    };
    
    input.click();
}

let createdRoomData = null;

async function createRoom() {
    const relayUrl = document.getElementById('relayUrl').value;

    if (!relayUrl) {
        showToast('Please enter a relay URL', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/room/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ relay_url: relayUrl })
        });

        const data = await response.json();

        if (data.success) {
            createdRoomData = data;
            
            // Display invite link section
            document.getElementById('inviteLinkSection').classList.remove('hidden');
            document.getElementById('inviteLinkDisplay').value = data.invite_link;
            document.getElementById('roomIdDisplay').textContent = data.room_id_display;
            document.getElementById('roomKeyDisplay').textContent = data.room_key;
            
            // Generate QR code
            generateQRCode(data.invite_link);
            
            // Log activity
            addActivity('create', `Created room ${data.room_id_display}`);
            
            showToast('Room created successfully!', 'success');
        } else {
            showToast(data.error || 'Failed to create room', 'danger');
        }
    } catch (error) {
        showToast('Error creating room', 'danger');
    }
}

function copyInviteLink() {
    const inviteLink = document.getElementById('inviteLinkDisplay').value;
    if (inviteLink) {
        navigator.clipboard.writeText(inviteLink).then(() => {
            showToast('Invite link copied to clipboard!', 'success');
        }).catch(() => {
            showToast('Failed to copy invite link', 'danger');
        });
    }
}

async function joinCreatedRoom() {
    if (createdRoomData && createdRoomData.invite_link) {
        document.getElementById('inviteLink').value = createdRoomData.invite_link;
        await joinRoom();
    }
}

function generateQRCode(text) {
    const canvas = document.getElementById('qrCodeCanvas');
    if (canvas && typeof QRCode !== 'undefined') {
        QRCode.toCanvas(canvas, text, {
            width: 180,
            margin: 2,
            color: {
                dark: '#000000',
                light: '#ffffff'
            }
        }, function(error) {
            if (error) console.error(error);
        });
    }
}

function downloadQRCode() {
    const canvas = document.getElementById('qrCodeCanvas');
    if (canvas) {
        const link = document.createElement('a');
        link.download = 'p521-invite-qr.png';
        link.href = canvas.toDataURL();
        link.click();
        showToast('QR code downloaded!', 'success');
    }
}

// Dashboard Functions
function updateDashboardStats() {
    document.getElementById('statRooms').textContent = savedRooms.length;
    document.getElementById('statMessages').textContent = messagesSent;
    
    // Calculate session time
    const elapsed = Math.floor((Date.now() - sessionStartTime) / 1000);
    const minutes = Math.floor(elapsed / 60);
    const hours = Math.floor(minutes / 60);
    const displayTime = hours > 0 ? `${hours}h ${minutes % 60}m` : `${minutes}m`;
    document.getElementById('statUptime').textContent = displayTime;
    
    // Load trusted contacts count
    loadTrustedContactsCount();
}

async function loadTrustedContactsCount() {
    try {
        const response = await fetch('/api/trust/contacts');
        const data = await response.json();
        if (data.success) {
            document.getElementById('statContacts').textContent = data.contacts.length;
        }
    } catch (error) {
        console.error('Error loading contacts count:', error);
    }
}

function addActivity(type, message) {
    const activity = {
        type,
        message,
        timestamp: new Date().toISOString()
    };
    activityLog.unshift(activity);
    if (activityLog.length > 20) {
        activityLog.pop();
    }
    localStorage.setItem('activityLog', JSON.stringify(activityLog));
    loadActivityLog();
}

function loadActivityLog() {
    const container = document.getElementById('recentActivity');
    if (!container) return;
    
    if (activityLog.length === 0) {
        container.innerHTML = '<p class="text-muted">No recent activity</p>';
        return;
    }
    
    container.innerHTML = activityLog.slice(0, 5).map(activity => {
        const iconClass = activity.type === 'join' ? 'join' : 
                         activity.type === 'message' ? 'message' : 'create';
        const icon = activity.type === 'join' ? 'bi-door-open' : 
                    activity.type === 'message' ? 'bi-envelope' : 'bi-plus-circle';
        const time = new Date(activity.timestamp).toLocaleTimeString();
        
        return `
            <div class="activity-item">
                <div class="activity-icon ${iconClass}">
                    <i class="bi ${icon}"></i>
                </div>
                <div class="flex-grow-1">
                    <div>${activity.message}</div>
                    <small class="text-muted">${time}</small>
                </div>
            </div>
        `;
    }).join('');
}

async function leaveRoom() {
    if (currentRoomId) {
        try {
            await fetch(`/api/room/${currentRoomId}/leave`, { method: 'POST' });
            currentRoomId = null;
            document.getElementById('chatRoom').classList.add('hidden');
            document.getElementById('joinTab').classList.remove('hidden');
            document.getElementById('chatMessages').innerHTML = `
                <div class="message system">
                    Welcome to the secure E2E room. Messages are end-to-end encrypted.
                </div>
            `;
            showToast('Left room', 'info');
        } catch (error) {
            showToast('Error leaving room', 'danger');
        }
    }
}

// Chat Functions
async function sendMessage() {
    const messageInput = document.getElementById('messageInput');
    const message = messageInput.value.trim();

    if (!message || !currentRoomId) {
        return;
    }

    try {
        const response = await fetch(`/api/room/${currentRoomId}/message`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });

        const data = await response.json();

        if (data.success) {
            messageInput.value = '';
            messagesSent++;
            const messageData = {
                type: 'sent',
                content: message,
                timestamp: new Date().toISOString(),
                sender: 'You',
                id: Date.now(),
                selfDestruct: selfDestructEnabled ? selfDestructTime : null
            };
            messageHistory.push(messageData);
            displayMessage(messageData);
            
            // Log activity
            addActivity('message', 'Sent a message');
            
            // Reset self-destruct
            if (selfDestructEnabled) {
                selfDestructEnabled = false;
                document.getElementById('selfDestructOptions').classList.add('hidden');
            }
        } else {
            showToast(data.error || 'Failed to send message', 'danger');
        }
    } catch (error) {
        showToast('Error sending message', 'danger');
    }
}

function toggleSelfDestruct() {
    selfDestructEnabled = !selfDestructEnabled;
    const options = document.getElementById('selfDestructOptions');
    
    if (selfDestructEnabled) {
        options.classList.remove('hidden');
        selfDestructTime = parseInt(document.getElementById('destructTime').value);
    } else {
        options.classList.add('hidden');
    }
}

document.getElementById('destructTime')?.addEventListener('change', function() {
    selfDestructTime = parseInt(this.value);
});

function displayMessage(data) {
    const chatMessages = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    
    messageDiv.className = `message ${data.type}`;
    messageDiv.dataset.messageId = data.id || Date.now();
    
    const timestamp = new Date(data.timestamp).toLocaleTimeString();
    
    if (data.type === 'system') {
        messageDiv.innerHTML = `
            <div>${data.content}</div>
        `;
    } else {
        const processedContent = parseMarkdown(data.content);
        let timerHtml = '';
        let replyHtml = '';
        
        if (data.replyTo) {
            replyHtml = `
                <div class="message-reply">
                    <i class="bi bi-reply me-1"></i>
                    <strong>${data.replyTo.sender}:</strong> ${data.replyTo.content.substring(0, 50)}...
                </div>
            `;
        }
        
        if (data.selfDestruct) {
            timerHtml = `<div class="self-destruct-timer" id="timer-${data.id}">${formatTime(data.selfDestruct)}</div>`;
            startSelfDestructTimer(data.id, data.selfDestruct);
        }
        
        messageDiv.innerHTML = `
            ${timerHtml}
            ${replyHtml}
            <div class="message-sender">${data.sender}</div>
            <div class="markdown-content">${processedContent}</div>
            <div class="message-timestamp">${timestamp}</div>
            <div class="message-reactions" id="reactions-${data.id}"></div>
            <div class="d-flex gap-2 mt-2">
                <button class="btn btn-sm btn-link text-muted p-0" onclick="showEmojiPicker(${data.id})">
                    <i class="bi bi-emoji-smile"></i>
                </button>
                <button class="btn btn-sm btn-link text-muted p-0" onclick="replyToMessage(${data.id})">
                    <i class="bi bi-reply"></i>
                </button>
                <button class="btn btn-sm btn-link text-muted p-0" onclick="quoteMessage(${data.id})">
                    <i class="bi bi-quote"></i>
                </button>
            </div>
        `;
    }
    
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    
    // Play sound for received messages
    if (data.type === 'received' && soundEnabled) {
        playNotificationSound();
    }
    
    // Save to history
    messageHistory.push(data);
    localStorage.setItem('messageHistory', JSON.stringify(messageHistory));
}

function formatTime(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function startSelfDestructTimer(messageId, seconds) {
    let remaining = seconds;
    const timerElement = document.getElementById(`timer-${messageId}`);
    
    const interval = setInterval(() => {
        remaining--;
        if (timerElement) {
            timerElement.textContent = formatTime(remaining);
        }
        
        if (remaining <= 0) {
            clearInterval(interval);
            const messageDiv = document.querySelector(`[data-message-id="${messageId}"]`);
            if (messageDiv) {
                messageDiv.style.opacity = '0';
                messageDiv.style.transform = 'scale(0.8)';
                setTimeout(() => messageDiv.remove(), 300);
            }
        }
    }, 1000);
}

function parseMarkdown(text) {
    // Simple markdown parsing
    let html = escapeHtml(text);
    
    // Code blocks
    html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
    
    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    
    // Bold
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    
    // Italic
    html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
    
    // Blockquotes
    html = html.replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>');
    
    // Links
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');
    
    return html;
}

function showEmojiPicker(messageId) {
    const existingPicker = document.querySelector('.emoji-picker');
    if (existingPicker) {
        existingPicker.remove();
        return;
    }

    const messageDiv = document.querySelector(`[data-message-id="${messageId}"]`);
    if (!messageDiv) return;

    const emojis = ['👍', '❤️', '😂', '😮', '😢', '🔥', '🎉', '💯'];
    
    const picker = document.createElement('div');
    picker.className = 'emoji-picker';
    picker.innerHTML = emojis.map(emoji => 
        `<span class="emoji-btn" onclick="addReaction(${messageId}, '${emoji}')">${emoji}</span>`
    ).join('');
    
    messageDiv.appendChild(picker);
    
    // Close picker when clicking outside
    setTimeout(() => {
        document.addEventListener('click', function closePicker(e) {
            if (!picker.contains(e.target)) {
                picker.remove();
                document.removeEventListener('click', closePicker);
            }
        });
    }, 100);
}

function addReaction(messageId, emoji) {
    const reactionsDiv = document.getElementById(`reactions-${messageId}`);
    if (reactionsDiv) {
        const existingReaction = reactionsDiv.querySelector(`[data-emoji="${emoji}"]`);
        if (existingReaction) {
            const count = parseInt(existingReaction.textContent) + 1;
            existingReaction.textContent = `${emoji} ${count}`;
        } else {
            const reaction = document.createElement('span');
            reaction.className = 'reaction';
            reaction.dataset.emoji = emoji;
            reaction.textContent = `${emoji} 1`;
            reactionsDiv.appendChild(reaction);
        }
    }
    
    // Remove picker
    const picker = document.querySelector('.emoji-picker');
    if (picker) picker.remove();
}

function handleKeyPress(event) {
    if (event.key === 'Enter') {
        sendMessage();
    }
}

function toggleSearch() {
    const searchBar = document.getElementById('searchBar');
    searchBar.classList.toggle('hidden');
    if (!searchBar.classList.contains('hidden')) {
        document.getElementById('messageSearch').focus();
    }
}

function searchMessages() {
    const searchTerm = document.getElementById('messageSearch').value.toLowerCase();
    const messages = document.querySelectorAll('#chatMessages .message:not(.system)');
    
    messages.forEach(msg => {
        const content = msg.textContent.toLowerCase();
        if (searchTerm && content.includes(searchTerm)) {
            msg.style.display = 'block';
            msg.classList.add('search-highlight');
        } else if (searchTerm) {
            msg.style.display = 'none';
        } else {
            msg.style.display = 'block';
            msg.classList.remove('search-highlight');
        }
    });
}

function clearSearch() {
    document.getElementById('messageSearch').value = '';
    searchMessages();
    document.getElementById('searchBar').classList.add('hidden');
}

let typingTimeout;
function handleTyping() {
    // Send typing indicator to server (would need WebSocket implementation)
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
        // Stop typing indicator after 2 seconds of no typing
    }, 2000);
}

function toggleEmojiPicker() {
    const input = document.getElementById('messageInput');
    const emojis = ['😀', '😂', '😍', '👍', '🎉', '🔥', '❤️', '👋', '🤔', '😎', '🙏', '💯'];
    
    // Simple emoji picker - insert random emoji for now
    const emoji = emojis[Math.floor(Math.random() * emojis.length)];
    input.value += emoji;
    input.focus();
}

function replyToMessage(messageId) {
    const message = messageHistory.find(m => m.id === messageId);
    if (message) {
        replyingTo = message;
        const input = document.getElementById('messageInput');
        input.placeholder = `Replying to ${message.sender}...`;
        input.focus();
        showToast('Reply mode enabled', 'info');
    }
}

function quoteMessage(messageId) {
    const message = messageHistory.find(m => m.id === messageId);
    if (message) {
        const input = document.getElementById('messageInput');
        input.value = `> ${message.content}\n\n`;
        input.focus();
    }
}

function playNotificationSound() {
    // Create a simple beep sound using Web Audio API
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.value = 800;
        oscillator.type = 'sine';
        gainNode.gain.value = 0.1;
        
        oscillator.start();
        oscillator.stop(audioContext.currentTime + 0.1);
    } catch (e) {
        console.error('Could not play sound:', e);
    }
}

function toggleSound() {
    soundEnabled = !soundEnabled;
    localStorage.setItem('soundEnabled', soundEnabled);
    showToast(soundEnabled ? 'Sound enabled' : 'Sound disabled', 'info');
}

function loadMessageHistory() {
    const saved = localStorage.getItem('messageHistory');
    if (saved) {
        try {
            messageHistory = JSON.parse(saved);
        } catch (e) {
            console.error('Error loading message history:', e);
        }
    }
}

// File Upload
function showFileUpload() {
    const modal = new bootstrap.Modal(document.getElementById('fileUploadModal'));
    modal.show();
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        document.getElementById('fileInfo').classList.remove('hidden');
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileSize').textContent = formatFileSize(file.size);
    }
}

function uploadFile() {
    showToast('File upload requires WebSocket integration', 'info');
    showToast('This feature is coming soon', 'info');
    
    const modal = bootstrap.Modal.getInstance(document.getElementById('fileUploadModal'));
    modal.hide();
}

// Participants
function showParticipants() {
    showToast('Participant list will be updated as people join', 'info');
}

// Settings
async function saveSettings() {
    const displayName = document.getElementById('settingsDisplayName').value;
    const maxFileSize = document.getElementById('maxFileSize').value;

    try {
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ display_name: displayName, max_file_size: maxFileSize })
        });

        const data = await response.json();

        if (data.success) {
            document.getElementById('currentUser').textContent = displayName;
            showToast('Settings saved!', 'success');
        } else {
            showToast(data.error || 'Failed to save settings', 'danger');
        }
    } catch (error) {
        showToast('Error saving settings', 'danger');
    }
}

// Utility Functions
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    const toastId = 'toast-' + Date.now();
    
    const toastHTML = `
        <div id="${toastId}" class="toast align-items-center text-white bg-${type} border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    
    toastContainer.insertAdjacentHTML('beforeend', toastHTML);
    
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, { delay: 3000 });
    toast.show();
    
    toastElement.addEventListener('hidden.bs.toast', () => {
        toastElement.remove();
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Theme Management
function toggleTheme() {
    currentTheme = currentTheme === 'light' ? 'dark' : 'light';
    localStorage.setItem('theme', currentTheme);
    applyTheme();
}

function applyTheme() {
    document.documentElement.setAttribute('data-theme', currentTheme);
    const icon = document.getElementById('themeIcon');
    if (icon) {
        icon.className = currentTheme === 'light' ? 'bi bi-moon-stars' : 'bi bi-sun';
    }
}

// Keyboard Shortcuts
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl + D: Toggle theme
        if (e.ctrlKey && e.key === 'd') {
            e.preventDefault();
            toggleTheme();
        }
        
        // Ctrl + F: Search messages
        if (e.ctrlKey && e.key === 'f') {
            e.preventDefault();
            showSearch();
        }
        
        // Ctrl + U: Upload file
        if (e.ctrlKey && e.key === 'u') {
            e.preventDefault();
            showFileUpload();
        }
        
        // Ctrl + L: Leave room
        if (e.ctrlKey && e.key === 'l') {
            e.preventDefault();
            leaveRoom();
        }
        
        // Ctrl + /: Show shortcuts
        if (e.ctrlKey && e.key === '/') {
            e.preventDefault();
            toggleShortcuts();
        }
        
        // Escape: Close modals/panels
        if (e.key === 'Escape') {
            const shortcutsPanel = document.getElementById('shortcutsPanel');
            if (shortcutsPanel && !shortcutsPanel.classList.contains('hidden')) {
                toggleShortcuts();
            }
        }
    });
}

function toggleShortcuts() {
    const panel = document.getElementById('shortcutsPanel');
    panel.classList.toggle('hidden');
}

function showSearch() {
    const searchTerm = prompt('Search messages:');
    if (searchTerm) {
        searchMessages(searchTerm);
    }
}

function searchMessages(term) {
    const results = messageHistory.filter(msg => 
        msg.content.toLowerCase().includes(term.toLowerCase())
    );
    
    if (results.length === 0) {
        showToast('No messages found', 'info');
        return;
    }
    
    showToast(`Found ${results.length} messages`, 'success');
    
    // Highlight first result
    const firstResult = results[0];
    const messageDiv = document.querySelector(`[data-message-id="${firstResult.id}"]`);
    if (messageDiv) {
        messageDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
        messageDiv.style.animation = 'pulse 0.5s ease 3';
        setTimeout(() => messageDiv.style.animation = '', 1500);
    }
}

// Drag and Drop
function setupDragAndDrop() {
    const chatContainer = document.getElementById('chatMessages');
    if (!chatContainer) return;

    chatContainer.addEventListener('dragover', (e) => {
        e.preventDefault();
        chatContainer.classList.add('drag-over');
    });

    chatContainer.addEventListener('dragleave', (e) => {
        e.preventDefault();
        chatContainer.classList.remove('drag-over');
    });

    chatContainer.addEventListener('drop', (e) => {
        e.preventDefault();
        chatContainer.classList.remove('drag-over');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleDroppedFile(files[0]);
        }
    });
}

function handleDroppedFile(file) {
    if (file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const modal = new bootstrap.Modal(document.getElementById('fileUploadModal'));
            modal.show();
            
            document.getElementById('fileInfo').classList.remove('hidden');
            document.getElementById('fileName').textContent = file.name;
            document.getElementById('fileSize').textContent = formatFileSize(file.size);
            
            // Add image preview
            const preview = document.createElement('img');
            preview.src = e.target.result;
            preview.className = 'image-preview';
            document.getElementById('fileInfo').insertBefore(preview, document.getElementById('fileInfo').firstChild);
        };
        reader.readAsDataURL(file);
    } else {
        showToast('File dropped - upload feature coming soon', 'info');
    }
}
