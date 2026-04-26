// P-521 Web UI - Premium Frontend Controller
// Keeps the original backend API contract while upgrading UX, rendering safety, and UI state handling.

const socket = typeof io === 'function' ? io() : null;

let currentRoomId = null;
let currentUserId = null;
let currentTheme = localStorage.getItem('theme') || 'dark';
let savedRooms = safeJSON(localStorage.getItem('savedRooms'), []);
let messageHistory = safeJSON(localStorage.getItem('messageHistory'), []);
let activityLog = safeJSON(localStorage.getItem('activityLog'), []);
let selfDestructEnabled = false;
let selfDestructTime = 30;
let sessionStartTime = Date.now();
let messagesSent = Number(localStorage.getItem('messagesSent') || '0');
let soundEnabled = localStorage.getItem('soundEnabled') !== 'false';
let replyingTo = null;
let createdRoomData = null;
let typingTimeout = null;

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
const byId = (id) => document.getElementById(id);

const UI = {
    tabs: ['dashboard', 'join', 'host', 'rooms', 'trust', 'settings', 'help'],
    emojiSet: ['😀', '😂', '😍', '👍', '🎉', '🔥', '❤️', '👋', '🤔', '😎', '🙏', '💯', '⚡', '🛡️', '👁️', '🌙', '✨', '🚀'],
    reactionSet: ['👍', '❤️', '😂', '😮', '😢', '🔥', '🎉', '💯', '🛡️', '⚡'],
    emptyRooms: `<div class="empty-state"><i class="bi bi-chat-dots"></i><p>No rooms yet. Join a room to get started.</p></div>`,
    emptyContacts: `<div class="empty-state"><i class="bi bi-person-check"></i><p>No trusted contacts yet.</p></div>`,
    welcomeMessage: `<div class="message system">Welcome to the secure E2E room. Messages are end-to-end encrypted.</div>` 
};

document.addEventListener('DOMContentLoaded', initApp);

function initApp() {
    applyTheme();
    setupSocketListeners();
    setupKeyboardShortcuts();
    setupDragAndDrop();
    setupRoomSearch();
    setupSelfDestructControl();
    updateDashboardStats();
    loadActivityLog();
    setInterval(updateDashboardStats, 60_000);
    checkAutoLogin();
}

async function checkAutoLogin() {
    try {
        const response = await fetch('/api/auto-login');
        const data = await safeResponseJSON(response);

        if (data?.success && data.auto_logged_in) {
            if (typeof AUTO_PASSWORD !== 'undefined') {
                sessionStorage.setItem('password', AUTO_PASSWORD);
            }

            enterApp(data.display_name, data.fingerprint);
            showToast('Auto-logged in from CLI.', 'success');

            if (data.invite_link) {
                byId('inviteLink').value = data.invite_link;
                await joinRoom();
            }

            return;
        }
    } catch (_) {
        // Auto-login is optional.
    }

    checkIdentityStatus();
}

function setupSocketListeners() {
    if (!socket) {
        console.warn('Socket.io is not available. Realtime updates disabled.');
        return;
    }

    socket.on('connect', () => setConnectionState(true));
    socket.on('disconnect', () => setConnectionState(false));
    socket.on('joined', (data) => console.log('Joined room:', data.room_id));
    socket.on('message', (data) => displayMessage(data));
}

function setConnectionState(isOnline) {
    const status = byId('connectionStatus');
    if (!status) return;

    status.classList.toggle('status-online', isOnline);
    status.classList.toggle('status-offline', !isOnline);
}

async function checkIdentityStatus() {
    try {
        const response = await fetch('/api/identity/status');
        const data = await safeResponseJSON(response);

        data?.exists ? showLoginForm() : showNewIdentityForm();
    } catch (error) {
        showToast('Error checking identity status.', 'danger');
    }
}

function showNewIdentityForm() {
    byId('newIdentityForm')?.classList.remove('hidden');
    byId('loginForm')?.classList.add('hidden');
}

function showLoginForm() {
    byId('newIdentityForm')?.classList.add('hidden');
    byId('loginForm')?.classList.remove('hidden');
    byId('loginPassword')?.focus();
}

async function createIdentity() {
    const displayName = byId('displayName')?.value.trim();
    const password = byId('newPassword')?.value || '';
    const confirmPassword = byId('confirmPassword')?.value || '';

    if (!displayName || !password) return showToast('Please fill in all fields.', 'warning');
    if (password !== confirmPassword) return showToast('Passwords do not match.', 'warning');
    if (password.length < 8) return showToast('Password must be at least 8 characters.', 'warning');

    try {
        const response = await fetch('/api/identity/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                password,
                display_name: displayName
            })
        });

        const data = await safeResponseJSON(response);

        if (data?.success) {
            showToast('Identity created successfully.', 'success');
            await loginWithPassword(password);
        } else {
            showToast(data?.error || 'Failed to create identity.', 'danger');
        }
    } catch (error) {
        showToast('Error creating identity.', 'danger');
    }
}

function login() {
    loginWithPassword(byId('loginPassword')?.value || '');
}

async function loginWithPassword(password) {
    if (!password) return showToast('Enter your password.', 'warning');

    try {
        const response = await fetch('/api/identity/load', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });

        const data = await safeResponseJSON(response);

        if (data?.success) {
            sessionStorage.setItem('password', password);
            enterApp(data.display_name, data.fingerprint);
            showToast('Logged in successfully.', 'success');
        } else {
            showToast(data?.error || 'Login failed.', 'danger');
        }
    } catch (error) {
        showToast('Error logging in.', 'danger');
    }
}

function enterApp(displayName = 'User', fingerprint = '') {
    byId('loginScreen')?.classList.add('hidden');
    byId('mainApp')?.classList.remove('hidden');

    setText('currentUser', displayName);
    setValue('settingsDisplayName', displayName);
    setText('identityFingerprint', fingerprint);
    setText('trustFingerprint', fingerprint);
    setText('yourFingerprint', fingerprint ? `${fingerprint.substring(0, 18)}...` : 'fingerprint unavailable');

    renderParticipantSelf(displayName, fingerprint);
    showTab('dashboard');
}

function logout() {
    if (currentRoomId) leaveRoom();

    sessionStorage.removeItem('password');

    byId('mainApp')?.classList.add('hidden');
    byId('loginScreen')?.classList.remove('hidden');

    setValue('loginPassword', '');

    showToast('Logged out.', 'info');
}

function showTab(tabName, event) {
    if (!UI.tabs.includes(tabName)) return;

    UI.tabs.forEach(tab => byId(`${tabName}Tab`)?.classList.add('hidden'));
    byId('chatRoom')?.classList.add('hidden');

    byId(`${tabName}Tab`)?.classList.remove('hidden');

    $$('#mainTabs .nav-link').forEach(link => link.classList.remove('active'));

    const activeLink = event?.currentTarget || $(`#mainTabs .nav-link[data-tab="${tabName}"]`);
    activeLink?.classList.add('active');

    if (tabName === 'rooms') loadRoomList();
    if (tabName === 'trust') loadTrustInfo();
    if (tabName === 'dashboard') updateDashboardStats();
    if (tabName === 'settings') syncSettingsControls();
}

async function joinRoom() {
    const inviteLink = byId('inviteLink')?.value.trim();

    if (!inviteLink) return showToast('Please enter an invite link.', 'warning');

    try {
        const response = await fetch('/api/room/join', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ invite_link: inviteLink })
        });

        const data = await safeResponseJSON(response);

        if (data?.success) {
            currentRoomId = data.room_id;

            setText('roomTitle', `Room: ${data.room_id_display}`);

            hideAllMainSections();
            byId('chatRoom')?.classList.remove('hidden');

            saveRoom(data.room_id_display, inviteLink);

            socket?.emit('join_room', { room_id: currentRoomId });

            addActivity('join', `Joined room ${data.room_id_display}`);
            showToast('Joined room successfully.', 'success');
        } else {
            showToast(data?.error || 'Failed to join room.', 'danger');
        }
    } catch (error) {
        showToast('Error joining room.', 'danger');
    }
}

function hideAllMainSections() {
    UI.tabs.forEach(tab => byId(`${tab}Tab`)?.classList.add('hidden'));
    $$('#mainTabs .nav-link').forEach(link => link.classList.remove('active'));
}

function saveRoom(roomId, inviteLink) {
    if (!roomId || savedRooms.some(room => room.id === roomId)) return;

    savedRooms.unshift({
        id: roomId,
        inviteLink,
        joinedAt: new Date().toISOString()
    });

    savedRooms = savedRooms.slice(0, 50);

    localStorage.setItem('savedRooms', JSON.stringify(savedRooms));
}

function loadRoomList(filter = '') {
    const roomList = byId('roomList');
    if (!roomList) return;

    const normalized = filter.trim().toLowerCase();
    const rooms = savedRooms.filter(room => !normalized || room.id.toLowerCase().includes(normalized));

    if (!rooms.length) {
        roomList.innerHTML = UI.emptyRooms;
        return;
    }

    roomList.replaceChildren(...rooms.map(room => createRoomNode(room)));
}

function createRoomNode(room) {
    const item = document.createElement('div');
    item.className = `room-item${currentRoomId && room.id === currentRoomId ? ' active' : ''}`;
    item.addEventListener('click', () => rejoinRoom(room.id));

    const joinedDate = new Date(room.joinedAt);

    item.innerHTML = `
        <div class="d-flex justify-content-between align-items-start gap-3">
            <div class="min-w-0">
                <div class="fw-bold mb-1">
                    <i class="bi bi-door-open me-2 text-info"></i>
                    <span class="room-title"></span>
                </div>
                <small class="text-muted">
                    <i class="bi bi-clock me-1"></i>
                    Joined ${escapeHtml(getTimeAgo(joinedDate))}
                </small>
            </div>

            <div class="dropdown">
                <button class="btn btn-sm btn-outline-secondary" type="button" data-bs-toggle="dropdown" aria-label="Room actions">
                    <i class="bi bi-three-dots-vertical"></i>
                </button>

                <ul class="dropdown-menu dropdown-menu-end">
                    <li>
                        <button class="dropdown-item" type="button" data-action="copy">
                            <i class="bi bi-clipboard me-2"></i>Copy Link
                        </button>
                    </li>

                    <li>
                        <button class="dropdown-item text-danger" type="button" data-action="delete">
                            <i class="bi bi-trash me-2"></i>Delete
                        </button>
                    </li>
                </ul>
            </div>
        </div>
    `;

    $('.room-title', item).textContent = room.id;

    $('[data-action="copy"]', item).addEventListener('click', (event) => {
        event.stopPropagation();
        copyRoomLink(room.inviteLink);
    });

    $('[data-action="delete"]', item).addEventListener('click', (event) => {
        event.stopPropagation();
        deleteRoom(room.id);
    });

    return item;
}

function setupRoomSearch() {
    byId('roomSearch')?.addEventListener('input', event => loadRoomList(event.target.value));
}

function getTimeAgo(date) {
    const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));

    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;

    return date.toLocaleDateString();
}

async function copyRoomLink(inviteLink) {
    try {
        await navigator.clipboard.writeText(inviteLink);
        showToast('Room link copied.', 'success');
    } catch (_) {
        showToast('Failed to copy link.', 'danger');
    }
}

function deleteRoom(roomId) {
    if (!confirm('Delete this room from your saved list?')) return;

    savedRooms = savedRooms.filter(room => room.id !== roomId);

    localStorage.setItem('savedRooms', JSON.stringify(savedRooms));

    loadRoomList(byId('roomSearch')?.value || '');
    showToast('Room deleted.', 'info');
}

async function rejoinRoom(roomId) {
    const room = savedRooms.find(item => item.id === roomId);
    if (!room) return;

    setValue('inviteLink', room.inviteLink);
    await joinRoom();
}

function loadTrustInfo() {
    setText('trustFingerprint', byId('identityFingerprint')?.textContent || '');
    loadTrustedContacts();
}

async function loadTrustedContacts() {
    try {
        const response = await fetch('/api/trust/contacts');
        const data = await safeResponseJSON(response);
        const contactsDiv = byId('trustedContacts');

        if (!contactsDiv) return;

        if (data?.success && Array.isArray(data.contacts) && data.contacts.length > 0) {
            contactsDiv.replaceChildren(...data.contacts.map(createContactNode));
        } else {
            contactsDiv.innerHTML = UI.emptyContacts;
        }
    } catch (error) {
        console.error('Error loading trusted contacts:', error);
    }
}

function createContactNode(contact) {
    const node = document.createElement('div');
    node.className = 'participant-item';

    const name = contact.name || 'Unknown';
    const fingerprint = contact.fingerprint || '';

    node.innerHTML = `
        <div class="participant-avatar"></div>
        <div class="min-w-0">
            <div class="fw-bold contact-name"></div>
            <small class="text-muted contact-fp"></small>
        </div>
    `;

    $('.participant-avatar', node).textContent = name.charAt(0).toUpperCase();
    $('.contact-name', node).textContent = name;
    $('.contact-fp', node).textContent = fingerprint ? `${fingerprint.substring(0, 18)}...` : 'fingerprint unavailable';

    return node;
}

async function exportIdentity() {
    try {
        const response = await fetch('/api/identity/export');
        const data = await safeResponseJSON(response);

        if (!data?.success) return showToast(data?.error || 'Failed to export identity.', 'danger');

        const blob = new Blob([JSON.stringify(data.data, null, 2)], {
            type: 'application/json'
        });

        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        const shortFp = data.data?.fingerprint ? data.data.fingerprint.substring(0, 8) : 'backup';

        link.href = url;
        link.download = `p521_identity_${shortFp}.json`;

        document.body.appendChild(link);
        link.click();
        link.remove();

        URL.revokeObjectURL(url);

        showToast('Identity exported successfully.', 'success');
    } catch (error) {
        showToast('Error exporting identity.', 'danger');
    }
}

async function importIdentity() {
    const input = document.createElement('input');

    input.type = 'file';
    input.accept = '.json,application/json';

    input.onchange = async (event) => {
        const file = event.target.files?.[0];
        if (!file) return;

        try {
            const identityData = JSON.parse(await file.text());

            const response = await fetch('/api/identity/import', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data: identityData })
            });

            const data = await safeResponseJSON(response);

            if (data?.success) {
                showToast('Identity imported successfully.', 'success');
                loadTrustInfo();
            } else {
                showToast(data?.error || 'Failed to import identity.', 'danger');
            }
        } catch (error) {
            showToast('Error importing identity.', 'danger');
        }
    };

    input.click();
}

async function createRoom() {
    const relayUrl = byId('relayUrl')?.value.trim();

    if (!relayUrl) return showToast('Please enter a relay URL.', 'warning');

    try {
        const response = await fetch('/api/room/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ relay_url: relayUrl })
        });

        const data = await safeResponseJSON(response);

        if (data?.success) {
            createdRoomData = data;

            byId('inviteLinkSection')?.classList.remove('hidden');

            setValue('inviteLinkDisplay', data.invite_link);
            setText('roomIdDisplay', data.room_id_display);
            setText('roomKeyDisplay', data.room_key);

            generateQRCode(data.invite_link);
            addActivity('create', `Created room ${data.room_id_display}`);

            showToast('Room created successfully.', 'success');
        } else {
            showToast(data?.error || 'Failed to create room.', 'danger');
        }
    } catch (error) {
        showToast('Error creating room.', 'danger');
    }
}

async function copyInviteLink() {
    const inviteLink = byId('inviteLinkDisplay')?.value;
    if (!inviteLink) return;

    try {
        await navigator.clipboard.writeText(inviteLink);
        showToast('Invite link copied.', 'success');
    } catch (_) {
        showToast('Failed to copy invite link.', 'danger');
    }
}

async function joinCreatedRoom() {
    if (!createdRoomData?.invite_link) return;

    setValue('inviteLink', createdRoomData.invite_link);
    await joinRoom();
}

function generateQRCode(text) {
    const canvas = byId('qrCodeCanvas');

    if (!canvas || typeof QRCode === 'undefined') return;

    QRCode.toCanvas(canvas, text, {
        width: 190,
        margin: 2,
        color: {
            dark: '#06101a',
            light: '#ffffff'
        }
    }, (error) => error && console.error(error));
}

function downloadQRCode() {
    const canvas = byId('qrCodeCanvas');
    if (!canvas) return;

    const link = document.createElement('a');

    link.download = 'p521-invite-qr.png';
    link.href = canvas.toDataURL('image/png');

    link.click();

    showToast('QR code downloaded.', 'success');
}

function updateDashboardStats() {
    setText('statRooms', savedRooms.length);
    setText('statMessages', messagesSent);

    const elapsed = Math.floor((Date.now() - sessionStartTime) / 1000);
    const minutes = Math.floor(elapsed / 60);
    const hours = Math.floor(minutes / 60);

    setText('statUptime', hours > 0 ? `${hours}h ${minutes % 60}m` : `${minutes}m`);

    loadTrustedContactsCount();
}

async function loadTrustedContactsCount() {
    try {
        const response = await fetch('/api/trust/contacts');
        const data = await safeResponseJSON(response);

        if (data?.success) setText('statContacts', data.contacts?.length || 0);
    } catch (_) {
        // Optional dashboard telemetry.
    }
}

function addActivity(type, message) {
    activityLog.unshift({
        type,
        message,
        timestamp: new Date().toISOString()
    });

    activityLog = activityLog.slice(0, 20);

    localStorage.setItem('activityLog', JSON.stringify(activityLog));

    loadActivityLog();
}

function loadActivityLog() {
    const container = byId('recentActivity');
    if (!container) return;

    if (!activityLog.length) {
        container.innerHTML = '<p class="text-muted mb-0">No recent activity</p>';
        return;
    }

    container.replaceChildren(...activityLog.slice(0, 5).map(activity => {
        const map = {
            join: ['join', 'bi-door-open'],
            message: ['message', 'bi-envelope-paper'],
            create: ['create', 'bi-plus-circle']
        };

        const [iconClass, icon] = map[activity.type] || ['message', 'bi-activity'];

        const node = document.createElement('div');
        node.className = 'activity-item';

        node.innerHTML = `
            <div class="activity-icon ${iconClass}">
                <i class="bi ${icon}"></i>
            </div>

            <div class="flex-grow-1 min-w-0">
                <div class="activity-message"></div>
                <small class="text-muted">${escapeHtml(new Date(activity.timestamp).toLocaleString())}</small>
            </div>
        `;

        $('.activity-message', node).textContent = activity.message;

        return node;
    }));
}

async function leaveRoom() {
    if (!currentRoomId) return;

    try {
        await fetch(`/api/room/${encodeURIComponent(currentRoomId)}/leave`, {
            method: 'POST'
        });
    } catch (_) {
        // Still leave locally even if the relay call fails.
    }

    currentRoomId = null;

    byId('chatRoom')?.classList.add('hidden');
    byId('joinTab')?.classList.remove('hidden');

    $(`#mainTabs .nav-link[data-tab="join"]`)?.classList.add('active');

    if (byId('chatMessages')) byId('chatMessages').innerHTML = UI.welcomeMessage;

    showToast('Left room.', 'info');
}

async function sendMessage() {
    const messageInput = byId('messageInput');
    const message = messageInput?.value.trim();

    if (!message || !currentRoomId) return;

    const payload = { message };

    if (replyingTo) payload.reply_to = replyingTo.id;
    if (selfDestructEnabled) payload.self_destruct = selfDestructTime;

    try {
        const response = await fetch(`/api/room/${encodeURIComponent(currentRoomId)}/message`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await safeResponseJSON(response);

        if (data?.success) {
            messageInput.value = '';

            resetReplyMode();

            messagesSent++;

            localStorage.setItem('messagesSent', String(messagesSent));

            addActivity('message', 'Sent a message');
            updateDashboardStats();

            if (selfDestructEnabled) toggleSelfDestruct(false);
        } else {
            showToast(data?.error || 'Failed to send message.', 'danger');
        }
    } catch (error) {
        showToast('Error sending message.', 'danger');
    }
}

function setupSelfDestructControl() {
    byId('destructTime')?.addEventListener('change', function () {
        selfDestructTime = Number(this.value || 30);
    });
}

function toggleSelfDestruct(forceState) {
    selfDestructEnabled = typeof forceState === 'boolean' ? forceState : !selfDestructEnabled;

    byId('selfDestructOptions')?.classList.toggle('hidden', !selfDestructEnabled);

    selfDestructTime = Number(byId('destructTime')?.value || 30);

    showToast(selfDestructEnabled ? 'Self-destruct enabled for next message.' : 'Self-destruct disabled.', 'info');
}

function displayMessage(data = {}) {
    const chatMessages = byId('chatMessages');
    if (!chatMessages) return;

    const message = normalizeMessage(data);

    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${message.type}`;
    messageDiv.dataset.messageId = message.id;

    if (message.type === 'system') {
        messageDiv.textContent = message.content;
    } else {
        renderChatMessage(messageDiv, message);
    }

    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;

    if (message.type === 'received' && soundEnabled) playNotificationSound();

    messageHistory.push(message);
    messageHistory = messageHistory.slice(-500);

    localStorage.setItem('messageHistory', JSON.stringify(messageHistory));
}

function normalizeMessage(data) {
    return {
        id: data.id || `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        type: ['sent', 'received', 'system'].includes(data.type) ? data.type : 'received',
        sender: data.sender || (data.type === 'sent' ? 'You' : 'Unknown'),
        content: String(data.content ?? data.message ?? ''),
        timestamp: data.timestamp || new Date().toISOString(),
        replyTo: data.replyTo || data.reply_to || null,
        selfDestruct: data.selfDestruct || data.self_destruct || null
    };
}

function renderChatMessage(container, message) {
    if (message.selfDestruct) {
        const timer = document.createElement('div');

        timer.className = 'self-destruct-timer';
        timer.id = `timer-${cssEscape(message.id)}`;
        timer.textContent = formatTime(Number(message.selfDestruct));

        container.appendChild(timer);

        requestAnimationFrame(() => startSelfDestructTimer(message.id, Number(message.selfDestruct)));
    }

    if (message.replyTo) {
        const reply = document.createElement('div');

        reply.className = 'message-reply';

        const sender = message.replyTo.sender || 'Unknown';
        const content = String(message.replyTo.content || '').slice(0, 70);

        reply.textContent = `↳ ${sender}: ${content}${content.length >= 70 ? '...' : ''}`;

        container.appendChild(reply);
    }

    const sender = document.createElement('div');
    sender.className = 'message-sender';
    sender.textContent = message.sender;

    const content = document.createElement('div');
    content.className = 'markdown-content';
    content.innerHTML = parseMarkdown(message.content);

    const timestamp = document.createElement('div');
    timestamp.className = 'message-timestamp';
    timestamp.textContent = new Date(message.timestamp).toLocaleTimeString();

    const reactions = document.createElement('div');
    reactions.className = 'message-reactions';
    reactions.id = `reactions-${message.id}`;

    const actions = document.createElement('div');
    actions.className = 'message-actions';

    actions.innerHTML = `
        <button class="btn btn-sm btn-link p-0" type="button" data-action="emoji" title="React">
            <i class="bi bi-emoji-smile"></i>
        </button>

        <button class="btn btn-sm btn-link p-0" type="button" data-action="reply" title="Reply">
            <i class="bi bi-reply"></i>
        </button>

        <button class="btn btn-sm btn-link p-0" type="button" data-action="quote" title="Quote">
            <i class="bi bi-quote"></i>
        </button>
    `;

    $('[data-action="emoji"]', actions).addEventListener('click', () => showEmojiPicker(message.id));
    $('[data-action="reply"]', actions).addEventListener('click', () => replyToMessage(message.id));
    $('[data-action="quote"]', actions).addEventListener('click', () => quoteMessage(message.id));

    container.append(sender, content, timestamp, reactions, actions);
}

function formatTime(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;

    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function startSelfDestructTimer(messageId, seconds) {
    let remaining = Math.max(1, seconds);

    const timerElement = byId(`timer-${messageId}`);

    const interval = setInterval(() => {
        remaining--;

        if (timerElement) timerElement.textContent = formatTime(remaining);

        if (remaining <= 0) {
            clearInterval(interval);

            const messageDiv = document.querySelector(`[data-message-id="${cssEscape(messageId)}"]`);

            if (messageDiv) {
                messageDiv.style.opacity = '0';
                messageDiv.style.transform = 'scale(.92) translateY(8px)';

                setTimeout(() => messageDiv.remove(), 260);
            }
        }
    }, 1000);
}

function parseMarkdown(text) {
    let html = escapeHtml(text);

    html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/(^|\s)\*([^*]+)\*/g, '$1<em>$2</em>');
    html = html.replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>');
    html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
    html = html.replace(/\n/g, '<br>');

    return html;
}

function showEmojiPicker(messageId) {
    const existing = $('.emoji-picker');
    if (existing) existing.remove();

    const messageDiv = document.querySelector(`[data-message-id="${cssEscape(messageId)}"]`);
    if (!messageDiv) return;

    const picker = document.createElement('div');
    picker.className = 'emoji-picker';

    UI.reactionSet.forEach(emoji => {
        const button = document.createElement('span');

        button.className = 'emoji-btn';
        button.textContent = emoji;

        button.addEventListener('click', (event) => {
            event.stopPropagation();
            addReaction(messageId, emoji);
        });

        picker.appendChild(button);
    });

    messageDiv.appendChild(picker);

    setTimeout(() => {
        document.addEventListener('click', function closePicker(event) {
            if (!picker.contains(event.target)) {
                picker.remove();
                document.removeEventListener('click', closePicker);
            }
        });
    }, 0);
}

function addReaction(messageId, emoji) {
    const reactionsDiv = byId(`reactions-${messageId}`);
    if (!reactionsDiv) return;

    let reaction = reactionsDiv.querySelector(`[data-emoji="${CSS.escape(emoji)}"]`);

    if (reaction) {
        const nextCount = Number(reaction.dataset.count || '1') + 1;

        reaction.dataset.count = String(nextCount);
        reaction.textContent = `${emoji} ${nextCount}`;
    } else {
        reaction = document.createElement('span');

        reaction.className = 'reaction';
        reaction.dataset.emoji = emoji;
        reaction.dataset.count = '1';
        reaction.textContent = `${emoji} 1`;

        reactionsDiv.appendChild(reaction);
    }

    $('.emoji-picker')?.remove();
}

function handleMessageKeyDown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
}

function handleKeyPress(event) {
    handleMessageKeyDown(event);
}

function toggleSearch() {
    const searchBar = byId('searchBar');

    searchBar?.classList.toggle('hidden');

    if (!searchBar?.classList.contains('hidden')) byId('messageSearch')?.focus();
}

function searchVisibleMessages() {
    const searchTerm = (byId('messageSearch')?.value || '').toLowerCase();

    $$('#chatMessages .message:not(.system)').forEach(message => {
        const match = !searchTerm || message.textContent.toLowerCase().includes(searchTerm);

        message.style.display = match ? 'block' : 'none';
        message.classList.toggle('search-highlight', Boolean(searchTerm && match));
    });
}

function clearSearch() {
    setValue('messageSearch', '');
    searchVisibleMessages();
    byId('searchBar')?.classList.add('hidden');
}

function searchMessages(term) {
    const query = String(term || '').trim().toLowerCase();

    if (!query) return;

    const results = messageHistory.filter(message => String(message.content || '').toLowerCase().includes(query));

    if (!results.length) return showToast('No messages found.', 'info');

    showToast(`Found ${results.length} message${results.length === 1 ? '' : 's'}.`, 'success');

    const target = document.querySelector(`[data-message-id="${cssEscape(results[0].id)}"]`);

    if (target) {
        target.scrollIntoView({
            behavior: 'smooth',
            block: 'center'
        });

        target.animate([
            {
                transform: 'scale(1)',
                boxShadow: 'var(--shadow-soft)'
            },
            {
                transform: 'scale(1.018)',
                boxShadow: 'var(--shadow), var(--glow)'
            },
            {
                transform: 'scale(1)',
                boxShadow: 'var(--shadow-soft)'
            }
        ], {
            duration: 900,
            iterations: 2
        });
    }
}

function handleTyping() {
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {}, 1200);
}

function toggleEmojiPicker() {
    const input = byId('messageInput');
    if (!input) return;

    const emoji = UI.emojiSet[Math.floor(Math.random() * UI.emojiSet.length)];
    const start = input.selectionStart ?? input.value.length;
    const end = input.selectionEnd ?? input.value.length;

    input.value = `${input.value.slice(0, start)}${emoji}${input.value.slice(end)}`;

    input.focus();

    input.selectionStart = input.selectionEnd = start + emoji.length;
}

function replyToMessage(messageId) {
    const message = messageHistory.find(item => String(item.id) === String(messageId));

    if (!message) return;

    replyingTo = message;

    const input = byId('messageInput');

    if (input) {
        input.placeholder = `Replying to ${message.sender} — Esc to cancel`;
        input.focus();
    }

    showToast('Reply mode enabled.', 'info');
}

function quoteMessage(messageId) {
    const message = messageHistory.find(item => String(item.id) === String(messageId));
    if (!message) return;

    const input = byId('messageInput');
    if (!input) return;

    input.value = `> ${message.content}\n\n`;
    input.focus();
}

function resetReplyMode() {
    replyingTo = null;

    const input = byId('messageInput');
    if (input) input.placeholder = 'Type a message...';
}

function playNotificationSound() {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gain = audioContext.createGain();

        oscillator.connect(gain);
        gain.connect(audioContext.destination);

        oscillator.frequency.value = 880;
        oscillator.type = 'sine';

        gain.gain.setValueAtTime(0.001, audioContext.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.075, audioContext.currentTime + 0.015);
        gain.gain.exponentialRampToValueAtTime(0.001, audioContext.currentTime + 0.12);

        oscillator.start();
        oscillator.stop(audioContext.currentTime + 0.13);
    } catch (error) {
        console.error('Could not play sound:', error);
    }
}

function toggleSound() {
    soundEnabled = byId('soundToggle') ? byId('soundToggle').checked : !soundEnabled;

    localStorage.setItem('soundEnabled', String(soundEnabled));

    showToast(soundEnabled ? 'Sound enabled.' : 'Sound disabled.', 'info');
}

function showFileUpload() {
    const modalEl = byId('fileUploadModal');

    if (!modalEl || typeof bootstrap === 'undefined') return;

    new bootstrap.Modal(modalEl).show();
}

function handleFileSelect(event) {
    const file = event.target.files?.[0];

    if (file) populateFileInfo(file);
}

function populateFileInfo(file, previewSrc = null) {
    byId('fileInfo')?.classList.remove('hidden');

    setText('fileName', file.name);
    setText('fileSize', formatFileSize(file.size));

    $$('#fileInfo .image-preview').forEach(img => img.remove());

    if (previewSrc) {
        const preview = document.createElement('img');

        preview.src = previewSrc;
        preview.className = 'image-preview';

        byId('fileInfo')?.prepend(preview);
    }
}

function uploadFile() {
    const progress = byId('uploadProgress');

    if (progress) progress.style.width = '100%';

    showToast('File upload requires relay/WebSocket integration.', 'info');

    const modal = bootstrap?.Modal?.getInstance(byId('fileUploadModal'));

    modal?.hide();

    setTimeout(() => {
        if (progress) progress.style.width = '0%';
    }, 500);
}

function showParticipants() {
    showToast('Participant list updates when the relay publishes join events.', 'info');
}

async function saveSettings() {
    const displayName = byId('settingsDisplayName')?.value.trim() || 'User';
    const maxFileSize = byId('maxFileSize')?.value || '100';

    try {
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                display_name: displayName,
                max_file_size: maxFileSize
            })
        });

        const data = await safeResponseJSON(response);

        if (data?.success) {
            setText('currentUser', displayName);
            renderParticipantSelf(displayName, byId('identityFingerprint')?.textContent || '');
            showToast('Settings saved.', 'success');
        } else {
            showToast(data?.error || 'Failed to save settings.', 'danger');
        }
    } catch (error) {
        showToast('Error saving settings.', 'danger');
    }
}

function syncSettingsControls() {
    if (byId('soundToggle')) byId('soundToggle').checked = soundEnabled;
    if (byId('themeToggle')) byId('themeToggle').checked = currentTheme === 'dark';
}

function showToast(message, type = 'info') {
    const toastContainer = byId('toastContainer');

    if (!toastContainer || typeof bootstrap === 'undefined') {
        return console.log(`[${type}] ${message}`);
    }

    const toastEl = document.createElement('div');

    toastEl.className = 'toast align-items-center border-0';
    toastEl.setAttribute('role', 'alert');

    toastEl.innerHTML = `
        <div class="d-flex">
            <div class="toast-body"></div>
            <button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;

    $('.toast-body', toastEl).textContent = message;

    const iconMap = {
        success: 'bi-check-circle',
        danger: 'bi-x-octagon',
        warning: 'bi-exclamation-triangle',
        info: 'bi-info-circle'
    };

    $('.toast-body', toastEl).insertAdjacentHTML('afterbegin', `<i class="bi ${iconMap[type] || iconMap.info} me-2"></i>`);

    toastContainer.appendChild(toastEl);

    const toast = new bootstrap.Toast(toastEl, {
        delay: 3200
    });

    toast.show();

    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
}

function toggleTheme() {
    currentTheme = currentTheme === 'light' ? 'dark' : 'light';

    localStorage.setItem('theme', currentTheme);

    applyTheme();
}

function applyTheme() {
    document.documentElement.setAttribute('data-theme', currentTheme);

    const icon = byId('themeIcon');

    if (icon) icon.className = currentTheme === 'light' ? 'bi bi-moon-stars' : 'bi bi-sun';

    if (byId('themeToggle')) byId('themeToggle').checked = currentTheme === 'dark';
}

function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            if (replyingTo) resetReplyMode();
            if (!byId('shortcutsPanel')?.classList.contains('hidden')) toggleShortcuts();
        }

        if (!event.ctrlKey) return;

        const key = event.key.toLowerCase();

        if (key === 'd') {
            event.preventDefault();
            toggleTheme();
        }

        if (key === 'f') {
            event.preventDefault();
            toggleSearch();
        }

        if (key === 'u') {
            event.preventDefault();
            showFileUpload();
        }

        if (key === 'l') {
            event.preventDefault();
            leaveRoom();
        }

        if (key === '/') {
            event.preventDefault();
            toggleShortcuts();
        }
    });
}

function toggleShortcuts() {
    byId('shortcutsPanel')?.classList.toggle('hidden');
}

function setupDragAndDrop() {
    const chatContainer = byId('chatMessages');

    if (!chatContainer) return;

    ['dragover', 'dragleave', 'drop'].forEach(eventName => {
        chatContainer.addEventListener(eventName, (event) => event.preventDefault());
    });

    chatContainer.addEventListener('dragover', () => chatContainer.classList.add('drag-over'));
    chatContainer.addEventListener('dragleave', () => chatContainer.classList.remove('drag-over'));

    chatContainer.addEventListener('drop', (event) => {
        chatContainer.classList.remove('drag-over');

        const file = event.dataTransfer.files?.[0];

        if (file) handleDroppedFile(file);
    });
}

function handleDroppedFile(file) {
    const modalEl = byId('fileUploadModal');

    if (modalEl && typeof bootstrap !== 'undefined') new bootstrap.Modal(modalEl).show();

    if (file.type.startsWith('image/')) {
        const reader = new FileReader();

        reader.onload = (event) => populateFileInfo(file, event.target.result);
        reader.readAsDataURL(file);
    } else {
        populateFileInfo(file);
    }
}

function renderParticipantSelf(displayName, fingerprint) {
    const participantList = byId('participantList');

    if (!participantList) return;

    const initial = (displayName || 'Y').charAt(0).toUpperCase();

    participantList.innerHTML = `
        <div class="participant-item">
            <div class="participant-avatar"></div>

            <div class="min-w-0">
                <div class="fw-bold participant-name"></div>
                <small class="text-muted" id="yourFingerprint"></small>
            </div>
        </div>
    `;

    $('.participant-avatar', participantList).textContent = initial;
    $('.participant-name', participantList).textContent = displayName || 'You';

    setText('yourFingerprint', fingerprint ? `${fingerprint.substring(0, 18)}...` : 'fingerprint unavailable');
}

function safeJSON(raw, fallback) {
    try {
        return raw ? JSON.parse(raw) : fallback;
    } catch (_) {
        return fallback;
    }
}

async function safeResponseJSON(response) {
    const text = await response.text();

    try {
        return text ? JSON.parse(text) : {};
    } catch (_) {
        return {};
    }
}

function escapeHtml(value) {
    const div = document.createElement('div');

    div.textContent = String(value ?? '');

    return div.innerHTML;
}

function cssEscape(value) {
    return typeof CSS !== 'undefined' && CSS.escape
        ? CSS.escape(String(value))
        : String(value).replace(/"/g, '\\"');
}

function formatFileSize(bytes) {
    if (!bytes) return '0 Bytes';

    const units = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);

    return `${Math.round((bytes / Math.pow(1024, index)) * 100) / 100} ${units[index]}`;
}

function setText(id, value) {
    const element = byId(id);

    if (element) element.textContent = value ?? '';
}

function setValue(id, value) {
    const element = byId(id);

    if (element) element.value = value ?? '';
}
