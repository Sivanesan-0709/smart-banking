// SMART BANKING DASHBOARD LOGIC (INR & ADAPTIVE BIOMETRIC IDENTITY LOCK)

// Global state
let currentUser = null;
let allTransactions = [];
let socket = null;
let liveRiskTimeout = null;
let liveFeedData = [];
let isFeedPaused = false;
let backgroundCanvas = null;
let backgroundCtx = null;
let particles = [];

// DOM load
document.addEventListener('DOMContentLoaded', () => {
    initParticles();
    checkAuthSession();
    initSocket();
    initLiveRiskMeter();
    loadModelMetrics();
    
    // Bind pause live feed checkbox
    const pauseCheckbox = document.getElementById('pauseLiveFeed');
    if (pauseCheckbox) {
        pauseCheckbox.addEventListener('change', (e) => {
            isFeedPaused = e.target.checked;
        });
    }
    
    // Bind live feed filter inputs
    const filterUser = document.getElementById('filterUser');
    if (filterUser) filterUser.addEventListener('input', renderLiveFeedTable);
    
    const filterRisk = document.getElementById('filterRisk');
    if (filterRisk) filterRisk.addEventListener('change', renderLiveFeedTable);
    
    const filterOutcome = document.getElementById('filterOutcome');
    if (filterOutcome) filterOutcome.addEventListener('change', renderLiveFeedTable);
    
    // Model Sandbox Inputs
    const sandboxForm = document.getElementById('sandboxForm');
    if (sandboxForm) {
        sandboxForm.addEventListener('input', runSandboxSimulation);
    }
});

// Particles background
function initParticles() {
    backgroundCanvas = document.getElementById('bgCanvas');
    if (!backgroundCanvas) return;
    backgroundCtx = backgroundCanvas.getContext('2d');
    
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    
    // Generate particles
    particles = [];
    const count = 60;
    for (let i = 0; i < count; i++) {
        particles.push({
            x: Math.random() * backgroundCanvas.width,
            y: Math.random() * backgroundCanvas.height,
            vx: (Math.random() - 0.5) * 0.4,
            vy: (Math.random() - 0.5) * 0.4,
            radius: Math.random() * 2 + 1,
            alpha: Math.random() * 0.5 + 0.1
        });
    }
    
    animateParticles();
}

function resizeCanvas() {
    if (backgroundCanvas) {
        backgroundCanvas.width = window.innerWidth;
        backgroundCanvas.height = window.innerHeight;
    }
}

function animateParticles() {
    if (!backgroundCanvas) return;
    backgroundCtx.clearRect(0, 0, backgroundCanvas.width, backgroundCanvas.height);
    
    // Draw connections
    backgroundCtx.beginPath();
    for (let i = 0; i < particles.length; i++) {
        const p1 = particles[i];
        p1.x += p1.vx;
        p1.y += p1.vy;
        
        // Boundaries
        if (p1.x < 0 || p1.x > backgroundCanvas.width) p1.vx *= -1;
        if (p1.y < 0 || p1.y > backgroundCanvas.height) p1.vy *= -1;
        
        backgroundCtx.fillStyle = `rgba(155, 93, 229, ${p1.alpha})`;
        backgroundCtx.beginPath();
        backgroundCtx.arc(p1.x, p1.y, p1.radius, 0, Math.PI * 2);
        backgroundCtx.fill();
        
        for (let j = i + 1; j < particles.length; j++) {
            const p2 = particles[j];
            const dist = Math.hypot(p1.x - p2.x, p1.y - p2.y);
            if (dist < 120) {
                backgroundCtx.strokeStyle = `rgba(0, 245, 212, ${0.12 - dist / 1000})`;
                backgroundCtx.lineWidth = 0.5;
                backgroundCtx.beginPath();
                backgroundCtx.moveTo(p1.x, p1.y);
                backgroundCtx.lineTo(p2.x, p2.y);
                backgroundCtx.stroke();
            }
        }
    }
    
    requestAnimationFrame(animateParticles);
}

// Session check
function checkAuthSession() {
    fetch('/api/profile')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                currentUser = data.user;
                showMainLayout();
            } else {
                showAuthLayout();
            }
        })
        .catch(() => showAuthLayout());
}

// Card switching
function toggleAuthCard(isRegister = null) {
    const loginCard = document.getElementById('loginCard');
    const registerCard = document.getElementById('registerCard');
    
    if (isRegister === true) {
        loginCard.classList.add('hidden');
        registerCard.classList.remove('hidden');
    } else if (isRegister === false) {
        loginCard.classList.remove('hidden');
        registerCard.classList.add('hidden');
    } else {
        loginCard.classList.toggle('hidden');
        registerCard.classList.toggle('hidden');
    }
}

function showAuthLayout() {
    document.getElementById('authSection').classList.remove('hidden');
    document.getElementById('dashboardSection').classList.add('hidden');
}

function showMainLayout() {
    document.getElementById('authSection').classList.add('hidden');
    document.getElementById('dashboardSection').classList.remove('hidden');
    
    // Switch tabs on startup
    if (currentUser.is_admin) {
        document.getElementById('adminNavBtn').classList.remove('hidden');
        switchTab('admin');
    } else {
        document.getElementById('adminNavBtn').classList.add('hidden');
        switchTab('dashboard');
    }
    
    loadDashboardData();
}

// Tab router
function switchTab(tabId) {
    document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
    
    const activeBtn = document.querySelector(`.nav-btn[onclick="switchTab('${tabId}')"]`);
    if (activeBtn) activeBtn.classList.add('active');
    
    const activeTab = document.getElementById(`tab-${tabId}`);
    if (activeTab) {
        activeTab.classList.add('active');
    }
    
    if (tabId === 'admin') {
        loadAdminData();
        if (socket && socket.connected) {
            socket.emit('join_admin');
        }
    }
}

// Auth handlers
function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    
    fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            currentUser = data.user;
            showToast('Login Success', data.message, 'success');
            showMainLayout();
        } else if (data.status === 'verification_required') {
            document.getElementById('loginMfaMaskedEmail').innerText = data.email_masked;
            document.getElementById('loginMfaModal').classList.remove('hidden');
            document.getElementById('loginMfaCode').focus();
        } else {
            showToast('Login Error', data.message || 'Invalid credentials.', 'error');
        }
    })
    .catch(() => showToast('Network Error', 'Could not establish connection.', 'error'));
}

function handleRegister(e) {
    e.preventDefault();
    try {
        console.log("handleRegister triggered");
        const username = document.getElementById('regUsername').value.trim();
        const firstname = document.getElementById('regFirstname').value.trim();
        const lastname = document.getElementById('regLastname').value.trim();
        const email = document.getElementById('regEmail').value.trim();
        const password = document.getElementById('regPassword').value;
        const confirm = document.getElementById('regConfirm').value;
        const phone = document.getElementById('regPhone').value.trim();
        const sex = document.getElementById('regSex').value;
        const address = document.getElementById('regAddress').value.trim();
        
        const balInput = document.getElementById('regBal');
        const bal = balInput ? parseFloat(balInput.value) : 50000;
        
        fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, firstname, lastname, email, password, confirm, phone, sex, address, bal })
        })
        .then(async res => {
            const data = await res.json();
            if (res.status === 200 && data.status === 'success') {
                showToast('Register Success', data.message, 'success');
                document.getElementById('registerForm').reset();
                toggleAuthCard(false); // Switch to login card
            } else {
                showToast('Register Error', data.message || 'Registration failed.', 'error');
            }
        })
        .catch((err) => {
            console.error("Register network error:", err);
            showToast('Network Error', 'Could not complete registration.', 'error');
        });
    } catch (err) {
        console.error("Registration JS crash caught:", err);
        showToast('Registration Error', 'Form error: ' + err.message, 'error');
        alert("Registration Error: " + err.message);
    }
}

function handleLogout() {
    fetch('/api/logout', { method: 'POST' })
        .then(() => {
            currentUser = null;
            showToast('Logged Out', 'Session terminated successfully.', 'info');
            showAuthLayout();
        });
    loadAdminReviewQueue();
}

// Client overview loaders
function loadDashboardData() {
    // 1. Profile details
    fetch('/api/profile')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                currentUser = data.user;
                document.getElementById('clientBalance').innerText = currentUser.balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
                // Populate profile settings form fields
                document.getElementById('profFirstname').value = currentUser.firstname;
                document.getElementById('profLastname').value = currentUser.lastname;
                document.getElementById('profEmail').value = currentUser.email;
                document.getElementById('profPhone').value = currentUser.phone;
                document.getElementById('profSex').value = currentUser.sex;
                document.getElementById('profAddress').value = currentUser.address;
            }
        });
        
    // 2. Fetch biometric face lock status
    loadBiometricStatus();
        
    // 3. Transactions List
    fetch('/api/transactions')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const list = document.getElementById('transactionsList');
                const badge = document.getElementById('txCountBadge');
                list.innerHTML = '';
                
                const txs = data.transactions;
                badge.innerText = `${txs.length} Records`;
                
                // Load charts and metrics
                currentTxs = txs;
                renderClientSpendChart(txs);
                loadDashboardMetrics();
                
                // Fetch dynamic analytics dashboard data (Feature 2)
                fetch('/api/analytics/dashboard')
                    .then(res => res.json())
                    .then(resData => {
                        if (resData.status === 'success') {
                            cachedAnalytics = resData.analytics;
                            switchAnalyticsChart(); // Update dynamic chart view
                        }
                    });
                
                // Fetch financial insights widget data (Feature 3)
                loadFinancialInsights();
                
                if (txs.length === 0) {
                    list.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No transactions recorded yet.</td></tr>`;
                    document.getElementById('clientNormalCount').innerText = '0';
                    document.getElementById('clientBlockedCount').innerText = '0';
                    return;
                }
                
                let normalCount = 0;
                let blockedCount = 0;
                
                txs.forEach(tx => {
                    const isSender = (tx.sender === currentUser.username);
                    const directionIcon = isSender ? '<i class="fa-solid fa-arrow-right-from-bracket text-danger"></i>' : '<i class="fa-solid fa-arrow-right-to-bracket text-success"></i>';
                    const targetName = isSender ? tx.receiver : tx.sender;
                    
                    let statusBadge = '';
                    if (tx.status === 'APPROVED') {
                        normalCount++;
                        statusBadge = `<span class="badge badge-success">Approved</span>`;
                    } else {
                        blockedCount++;
                        statusBadge = `<span class="badge badge-danger">Blocked</span>`;
                    }
                    
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${formatDate(tx.timestamp)}</td>
                        <td>${tx.type}</td>
                        <td>${directionIcon} ${targetName}</td>
                        <td class="font-heading font-bold">${isSender ? '-' : '+'}₹${tx.amount.toLocaleString()}</td>
                        <td>${statusBadge}</td>
                        <td>
                            <div style="display: flex; gap: 4px;">
                                <button class="btn btn-outline btn-sm" onclick="openXaiTrace(${tx.id})" style="padding: 2px 6px; font-size: 0.72rem; border-radius: 4px;">
                                    <i class="fa-solid fa-brain"></i> Explain
                                </button>
                                <button class="btn btn-accent btn-sm" onclick="downloadReceiptPDF(${tx.id})" style="padding: 2px 6px; font-size: 0.72rem; border-radius: 4px; background: #06b6d4; border-color: #06b6d4;">
                                    <i class="fa-solid fa-receipt"></i> Receipt
                                </button>
                            </div>
                        </td>
                    `;
                    list.appendChild(row);
                });
                
                document.getElementById('clientNormalCount').innerText = normalCount;
                document.getElementById('clientBlockedCount').innerText = blockedCount;
            }
        });
    loadWalletAnalytics();
}

// Profile update
function handleProfileUpdate(e) {
    e.preventDefault();
    const firstname = document.getElementById('profFirstname').value.trim();
    const lastname = document.getElementById('profLastname').value.trim();
    const email = document.getElementById('profEmail').value.trim();
    const phone = document.getElementById('profPhone').value.trim();
    const sex = document.getElementById('profSex').value;
    const address = document.getElementById('profAddress').value.trim();
    
    fetch('/api/profile/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ firstname, lastname, email, phone, sex, address })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            showToast('Profile Updated', data.message, 'success');
            loadDashboardData();
        } else {
            showToast('Update Error', data.message || 'Failed to save changes.', 'error');
        }
    })
    .catch(() => showToast('Network Error', 'Failed to submit updates.', 'error'));
}

// Purge account
function handleAccountDelete(e) {
    e.preventDefault();
    const password = document.getElementById('deletePasswordConfirm').value;
    if (!confirm("CRITICAL WARNING: Purging your account will permanently delete your identity files, balance tables, and face biometric patterns. This action is irreversible. Continue?")) return;
    
    fetch('/api/delete_account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            showToast('Account Purged', data.message, 'info');
            showAuthLayout();
        } else {
            showToast('Purge Error', data.message || 'Incorrect confirmation password.', 'error');
        }
    })
    .catch(() => showToast('Network Error', 'Connection failed.', 'error'));
}


// --- 1. Face Biometrics Enrollment Wizard ---
let enrollStream = null;
let enrollSamples = [];
const maxEnrollSamples = 3;
const enrollPoses = ['Straight', 'Straight', 'Straight'];
const enrollPoseInstructions = ['Look straight at the camera and keep your face clearly visible.', 'Look straight at the camera and keep your face clearly visible.', 'Look straight at the camera and keep your face clearly visible.'];

function loadBiometricStatus() {
    fetch('/api/biometric/status')
        .then(res => res.json())
        .then(data => {
            const text = document.getElementById('biometricStatusText');
            const badge = document.getElementById('biometricBadge');
            const enrollBtn = document.getElementById('enrollFaceBtn');
            const deleteBtn = document.getElementById('deleteFaceBtn');
            const card = document.getElementById('biometricStatusCard');
            const icon = document.getElementById('biometricIcon');

            if (!text || !badge || !enrollBtn) return;

            if (data.status === 'success' && data.enrolled) {
                text.innerText = "Secured";
                badge.className = "badge badge-success";
                badge.innerHTML = `<i class="fa-solid fa-lock"></i> Protected`;
                enrollBtn.innerText = "Re-enroll";
                deleteBtn.classList.remove('hidden');
                card.className = "metric-card balance-card glow-green";
                icon.innerHTML = `<i class="fa-solid fa-user-shield text-success"></i>`;
            } else {
                text.innerText = "Disabled";
                badge.className = "badge badge-danger";
                badge.innerHTML = `<i class="fa-solid fa-unlock"></i> Unprotected`;
                enrollBtn.innerText = "Enroll Face";
                deleteBtn.classList.add('hidden');
                card.className = "metric-card balance-card glow-purple";
                icon.innerHTML = `<i class="fa-solid fa-face-smile"></i>`;
            }
        });
}

function openEnrollmentModal() {
    document.getElementById('enrollmentModal').classList.remove('hidden');
    enrollSamples = [];
    document.getElementById('enrollFeedback').innerText = 'Please click Start Camera to begin.';
    updateEnrollProgress();
    document.getElementById('captureFrameBtn').classList.add('hidden');
    document.getElementById('startCameraBtn').classList.remove('hidden');
    document.getElementById('cameraPlaceholder').classList.remove('hidden');
}

function closeEnrollmentModal() {
    document.getElementById('enrollmentModal').classList.add('hidden');
    stopEnrollWebcam();
}

function stopEnrollWebcam() {
    if (enrollStream) {
        enrollStream.getTracks().forEach(track => track.stop());
        enrollStream = null;
    }
    const video = document.getElementById('enrollVideo');
    if (video) video.srcObject = null;
}

function initEnrollWebcam() {
    document.getElementById('enrollFeedback').innerText = 'Accessing camera device...';
    navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 640 }, height: { ideal: 480 } } })
        .then(stream => {
            enrollStream = stream;
            const video = document.getElementById('enrollVideo');
            video.srcObject = stream;
            document.getElementById('cameraPlaceholder').classList.add('hidden');
            document.getElementById('startCameraBtn').classList.add('hidden');
            document.getElementById('captureFrameBtn').classList.remove('hidden');
            
            console.log("Camera initialized successfully. Video stream active.");
            updatePoseInstructions();
        })
        .catch(err => {
            let msg = 'Could not open media stream.';
            if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
                msg = 'Camera permission was denied. Please allow camera access in browser settings.';
            } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
                msg = 'No camera device found on this system.';
            } else if (err.name === 'NotReadableError' || err.name === 'TrackStartError') {
                msg = 'Camera is in use by another application.';
            }
            document.getElementById('enrollFeedback').innerText = 'Camera Error: ' + msg;
            showToast('Camera Error', msg, 'error');
        });
}

function updateEnrollProgress() {
    for (let i = 1; i <= maxEnrollSamples; i++) {
        const dot = document.getElementById('sampleDot' + i);
        if (!dot) continue;
        if (i <= enrollSamples.length) {
            dot.className = "sample-dot success";
        } else if (i === enrollSamples.length + 1) {
            dot.className = "sample-dot active";
        } else {
            dot.className = "sample-dot";
        }
    }
}

function updatePoseInstructions() {
    const idx = enrollSamples.length;
    if (idx < maxEnrollSamples) {
        document.getElementById('enrollFeedback').innerText = `Capture ${idx+1}/3: ${enrollPoseInstructions[idx]}`;
    }
}

function captureEnrollSample() {
    if (!enrollStream) return;
    const video = document.getElementById('enrollVideo');
    const canvas = document.getElementById('enrollCanvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = video.videoWidth || 640;
    canvas.height = video.videoHeight || 480;
    
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const dataUrl = canvas.toDataURL('image/jpeg');
    
    console.log("Frame captured:", canvas.width, "x", canvas.height, "Base64 length:", dataUrl.length);
    
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
    let isBlank = true;
    for (let i = 4; i < imgData.length; i += 4) {
        if (imgData[i] !== imgData[0] || imgData[i+1] !== imgData[1] || imgData[i+2] !== imgData[2]) {
            isBlank = false;
            break;
        }
    }
    
    if (isBlank) {
        console.warn("Capture Error: Canvas frame is blank.");
        showToast('Capture Error', 'Webcam frame is blank/empty. Please retry.', 'error');
        return;
    }
    
    let sum = 0;
    for (let i = 0; i < imgData.length; i += 4) {
        sum += imgData[i];
    }
    const mean = sum / (imgData.length / 4);
    let variance = 0;
    for (let i = 0; i < imgData.length; i += 4) {
        variance += Math.pow(imgData[i] - mean, 2);
    }
    variance = variance / (imgData.length / 4);
    
    if (variance < 10) {
        console.warn("Capture Error: Canvas pixel variance too low (" + variance + ").");
        showToast('Capture Error', 'Image contrast is too low. Please improve lighting.', 'error');
        return;
    }
    
    const idx = enrollSamples.length;
    const pose = enrollPoses[idx];
    
    document.getElementById('enrollFeedback').innerText = `Validating quality for capture ${idx+1}/3...`;
    
    fetch('/api/biometric/enroll/sample', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image: dataUrl, index: idx, pose: pose })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            enrollSamples.push(dataUrl);
            updateEnrollProgress();
            
            showToast('Sample Accepted', data.message, 'success');
            
            if (enrollSamples.length >= maxEnrollSamples) {
                document.getElementById('captureFrameBtn').classList.add('hidden');
                document.getElementById('enrollFeedback').innerText = 'Analyzing face templates...';
                stopEnrollWebcam();
                submitEnrollTemplates();
            } else {
                updatePoseInstructions();
            }
        } else {
            console.warn("Backend rejected sample quality:", data.message);
            document.getElementById('enrollFeedback').innerText = `Quality Error: ${data.message} Please retry.`;
            showToast('Quality Error', data.message || 'Validation failed.', 'error');
        }
    })
    .catch(() => {
        showToast('Network Error', 'Connection to validation server failed.', 'error');
        updatePoseInstructions();
    });
}

function submitEnrollTemplates() {
    fetch('/api/biometric/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ images: enrollSamples })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            showToast('Enrollment Success', data.message, 'success');
            closeEnrollmentModal();
            loadBiometricStatus();
        } else {
            showToast('Enrollment Failed', data.message || 'Face analysis failed.', 'error');
            openEnrollmentModal();
        }
    })
    .catch(() => {
        showToast('Network Error', 'Biometric upload failed.', 'error');
        openEnrollmentModal();
    });
}

function deleteEnrollment() {
    if (!confirm("Are you sure you want to revoke and delete your biometric face template? Your high-risk transfers will no longer be protected by face verification.")) return;
    fetch('/api/biometric/delete', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showToast('Biometrics Revoked', data.message, 'info');
                loadBiometricStatus();
            } else {
                showToast('Error', data.message, 'error');
            }
        });
}


// --- 2. Adaptive MFA Transfer Flow ---
let mfaStream = null;
let mfaCheckInterval = null;
let faceAttempts = 0;
const maxFaceAttempts = 8;

function handleTransfer(e) {
    e.preventDefault();
    const submitBtn = document.querySelector('#transferForm button[type="submit"]');
    if (!submitBtn) return;
    
    // Check if already submitting
    if (submitBtn.disabled) return;
    
    // Disable button and show spinner
    submitBtn.disabled = true;
    const originalBtnHTML = submitBtn.innerHTML;
    submitBtn.innerHTML = '<span>Processing...</span> <i class="fa-solid fa-spinner fa-spin"></i>';
    
    const receiver = document.getElementById('txReceiver').value.trim();
    const amount = document.getElementById('txAmount').value;
    const type = document.getElementById('txType').value;

    fetch('/api/transfer/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ receiver, amount, type })
    })
    .then(async res => {
        const data = await res.json();
        
        // Re-enable button on completion
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnHTML;
        
        // Case A: Low Risk Auto-Approved
        if (res.status === 200 && data.status === 'success') {
            showToast('Transfer Approved', data.message, 'success');
            document.getElementById('transferForm').reset();
            loadDashboardData();
            // Show decision trace
            showDecisionTrace(data.new_balance, "LOW", 15, ["Standard parameters"], true, false, false);
        } 
        // Case B: Medium/High Risk Verification Required
        else if (data.status === 'verification_required') {
            // Store risk details for trace
            sessionStorage.setItem('current_risk_score', data.score);
            sessionStorage.setItem('current_risk_level', data.level);
            sessionStorage.setItem('current_reasons', JSON.stringify(data.reasons));
            
            openMfaModal(data);
        }
        // Case C: Critical Risk Blocked
        else if (data.status === 'blocked') {
            showToast('Blocked Attempt', 'Suspected threat vector blocked.', 'error');
            showSuspiciousBlockedAlert(data);
            showDecisionTrace(0, data.level, data.score, data.reasons, false, false, false, "Blocked by Threat Model");
            loadDashboardData();
        }
        else if (data.status === 'pending_review') {
            showToast('Review Required', 'Transaction queued for manual administrator review.', 'warning');
            document.getElementById('transferForm').reset();
            loadDashboardData();
            showDecisionTrace(0, data.level, data.score, data.reasons, false, false, false, "Pending Review");
        } else {
            showToast('Transfer Error', data.message || 'Error occurred.', 'error');
        }
    })
    .catch((err) => {
        // Re-enable button on failure
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnHTML;
        showToast('Network Error', 'Could not initiate transfer.', 'error');
    });
}

let otpExpiryInterval = null;
let resendCooldownInterval = null;

function startOtpTimer(durationSeconds) {
    if (otpExpiryInterval) clearInterval(otpExpiryInterval);
    let timeRemaining = durationSeconds;
    const timerSpan = document.getElementById('mfaOtpTimer');
    if (!timerSpan) return;
    
    function updateTimer() {
        const minutes = Math.floor(timeRemaining / 60);
        const seconds = timeRemaining % 60;
        timerSpan.innerText = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        if (timeRemaining <= 0) {
            clearInterval(otpExpiryInterval);
            timerSpan.innerText = "EXPIRED";
            showToast('OTP Expired', 'The OTP verification window has expired. Please initiate a new transaction.', 'error');
            const submitBtn = document.getElementById('mfaSubmitOtpBtn');
            if (submitBtn) submitBtn.disabled = true;
        }
        timeRemaining--;
    }
    updateTimer();
    otpExpiryInterval = setInterval(updateTimer, 1000);
}

function startResendCooldown(durationSeconds) {
    if (resendCooldownInterval) clearInterval(resendCooldownInterval);
    let cooldownRemaining = durationSeconds;
    const resendBtn = document.getElementById('mfaResendOtpBtn');
    if (!resendBtn) return;
    resendBtn.disabled = true;
    
    function updateCooldown() {
        if (cooldownRemaining <= 0) {
            clearInterval(resendCooldownInterval);
            resendBtn.innerText = "Resend OTP";
            resendBtn.disabled = false;
        } else {
            resendBtn.innerText = `Resend OTP (${cooldownRemaining}s)`;
            cooldownRemaining--;
        }
    }
    updateCooldown();
    resendCooldownInterval = setInterval(updateCooldown, 1000);
}

function openMfaModal(data) {
    document.getElementById('mfaModal').classList.remove('hidden');
    document.getElementById('mfaStepOtp').classList.remove('hidden');
    document.getElementById('mfaStepFace').classList.add('hidden');
    
    sessionStorage.setItem('mfa_transaction_token', data.transaction_token);
    sessionStorage.setItem('mfa_required', JSON.stringify(data.required));
    
    const emailSpan = document.getElementById('mfaMaskedEmail');
    if (emailSpan) emailSpan.innerText = data.masked_email;
    document.getElementById('mfaOtpCode').value = '';
    document.getElementById('mfaOtpCode').focus();
    
    const submitBtn = document.getElementById('mfaSubmitOtpBtn');
    if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<span>Confirm OTP</span> <i class="fa-solid fa-arrow-right"></i>';
    }
    
    faceAttempts = 0;
    
    startOtpTimer(data.expires_in || 300);
    startResendCooldown(60);
}

function closeMfaModal() {
    document.getElementById('mfaModal').classList.add('hidden');
    stopMfaWebcam();
    if (otpExpiryInterval) {
        clearInterval(otpExpiryInterval);
        otpExpiryInterval = null;
    }
    if (resendCooldownInterval) {
        clearInterval(resendCooldownInterval);
        resendCooldownInterval = null;
    }
}

function stopMfaWebcam() {
    if (mfaCheckInterval) {
        clearInterval(mfaCheckInterval);
        mfaCheckInterval = null;
    }
    if (mfaStream) {
        mfaStream.getTracks().forEach(track => track.stop());
        mfaStream = null;
    }
    const video = document.getElementById('mfaVideo');
    if (video) video.srcObject = null;
}

function handleMfaOtpSubmit(e) {
    e.preventDefault();
    const otp = document.getElementById('mfaOtpCode').value.trim();
    const transaction_token = sessionStorage.getItem('mfa_transaction_token');
    
    const submitBtn = document.getElementById('mfaSubmitOtpBtn');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span>Verifying...</span> <i class="fa-solid fa-spinner fa-spin"></i>';
    }
    
    fetch('/api/transfer/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ transaction_token, otp })
    })
    .then(async res => {
        const data = await res.json();
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<span>Confirm OTP</span> <i class="fa-solid fa-arrow-right"></i>';
        }
        
        if (res.status === 200) {
            if (data.status === 'success') {
                showToast('Transfer Approved', data.message, 'success');
                closeMfaModal();
                document.getElementById('transferForm').reset();
                loadDashboardData();
                
                showDecisionTrace(
                    data.new_balance,
                    sessionStorage.getItem('current_risk_level'),
                    sessionStorage.getItem('current_risk_score'),
                    JSON.parse(sessionStorage.getItem('current_reasons')),
                    true, true, false
                );
            } else if (data.status === 'otp_ok_need_face') {
                showToast('OTP Confirmed', 'Please proceed to Face Biometric verification.', 'info');
                document.getElementById('mfaStepOtp').classList.add('hidden');
                document.getElementById('mfaStepFace').classList.remove('hidden');
                initMfaVerificationChallenge();
            }
        } else {
            showToast('OTP Error', data.message || 'OTP verification failed.', 'error');
            document.getElementById('mfaOtpCode').value = '';
            document.getElementById('mfaOtpCode').focus();
        }
    })
    .catch(() => {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<span>Confirm OTP</span> <i class="fa-solid fa-arrow-right"></i>';
        }
        showToast('Network Error', 'Could not verify OTP code.', 'error');
    });
}

function handleMfaOtpResend() {
    const transaction_token = sessionStorage.getItem('mfa_transaction_token');
    const resendBtn = document.getElementById('mfaResendOtpBtn');
    if (!resendBtn) return;
    
    resendBtn.disabled = true;
    resendBtn.innerText = 'Sending...';
    
    fetch('/api/otp/resend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ transaction_token })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200) {
            showToast('OTP Resent', data.message, 'success');
            const submitBtn = document.getElementById('mfaSubmitOtpBtn');
            if (submitBtn) submitBtn.disabled = false;
            startOtpTimer(data.expires_in || 300);
            startResendCooldown(60);
        } else {
            showToast('Resend Error', data.message || 'Failed to resend verification code.', 'error');
            resendBtn.innerText = 'Resend OTP';
            resendBtn.disabled = false;
        }
    })
    .catch(() => {
        showToast('Network Error', 'Could not resend OTP code.', 'error');
        resendBtn.innerText = 'Resend OTP';
        resendBtn.disabled = false;
    });
}

function initMfaVerificationChallenge() {
    document.getElementById('livenessInstructionText').innerText = 'Requesting Challenge...';
    document.getElementById('mfaFaceFeedback').innerText = '';
    
    fetch('/api/biometric/verify/initiate', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const challenge = data.challenge;
                let challengeText = "";
                const arrow = document.getElementById('livenessArrow');
                arrow.className = "hidden";
                
                if (challenge === 'LOOK_LEFT') {
                    challengeText = "◀ TURN HEAD LEFT";
                    arrow.className = "left-arrow";
                    arrow.style.left = "20px";
                    arrow.style.top = "100px";
                } else if (challenge === 'LOOK_RIGHT') {
                    challengeText = "TURN HEAD RIGHT ▶";
                    arrow.className = "right-arrow";
                    arrow.style.right = "20px";
                    arrow.style.top = "100px";
                } else {
                    challengeText = "☉ LOOK STRAIGHT";
                    arrow.className = "straight-arrow";
                    arrow.style.left = "calc(50% - 24px)";
                    arrow.style.top = "calc(50% - 24px)";
                }
                
                document.getElementById('livenessInstructionText').innerText = challengeText;
                document.getElementById('mfaFaceStartBtn').classList.remove('hidden');
            }
        });
}

function initMfaWebcam() {
    document.getElementById('mfaFaceFeedback').innerText = 'Starting camera stream...';
    document.getElementById('mfaFaceStartBtn').classList.add('hidden');
    
    navigator.mediaDevices.getUserMedia({ video: { width: 320, height: 240 } })
        .then(stream => {
            mfaStream = stream;
            const video = document.getElementById('mfaVideo');
            video.srcObject = stream;
            
            // Loop frame analysis
            mfaCheckInterval = setInterval(captureMfaFrame, 1500);
        })
        .catch(err => {
            let msg = 'Could not open camera stream.';
            if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
                msg = 'Camera permission was denied. Please allow camera access in browser settings.';
            } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
                msg = 'No camera device found on this system.';
            } else if (err.name === 'NotReadableError' || err.name === 'TrackStartError') {
                msg = 'Camera is in use by another application.';
            }
            document.getElementById('mfaFaceFeedback').innerText = 'Camera Error: ' + msg;
            document.getElementById('mfaFaceStartBtn').classList.remove('hidden');
            showToast('Camera Error', msg, 'error');
        });
}

function captureMfaFrame() {
    if (!mfaStream) return;
    faceAttempts++;
    if (faceAttempts > maxFaceAttempts) {
        stopMfaWebcam();
        closeMfaModal();
        showToast('Verification Failed', 'Too many failed biometric attempts. Transaction aborted.', 'error');
        
        // Show trace failure
        showDecisionTrace(
            0,
            sessionStorage.getItem('current_risk_level'),
            sessionStorage.getItem('current_risk_score'),
            JSON.parse(sessionStorage.getItem('current_reasons')),
            false, true, false, "Biometric verification timeout/mismatch"
        );
        loadDashboardData();
        return;
    }
    
    const video = document.getElementById('mfaVideo');
    const canvas = document.getElementById('mfaCanvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = video.videoWidth || 320;
    canvas.height = video.videoHeight || 240;
    
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const dataUrl = canvas.toDataURL('image/jpeg');
    
    document.getElementById('mfaFaceFeedback').innerText = `Matching face (Attempt ${faceAttempts}/${maxFaceAttempts})...`;
    
    fetch('/api/biometric/verify/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image: dataUrl })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            stopMfaWebcam();
            closeMfaModal();
            showToast('Transfer Approved', data.message, 'success');
            document.getElementById('transferForm').reset();
            loadDashboardData();
            
            // Show successful decision trace
            showDecisionTrace(
                data.new_balance, 
                sessionStorage.getItem('current_risk_level'),
                sessionStorage.getItem('current_risk_score'),
                JSON.parse(sessionStorage.getItem('current_reasons')),
                true, true, true
            );
        } else {
            document.getElementById('mfaFaceFeedback').innerText = data.message || 'Verification mismatch.';
        }
    })
    .catch(() => {
        document.getElementById('mfaFaceFeedback').innerText = 'Biometric check connection error.';
    });
}

function showSuspiciousBlockedAlert(data) {
    const modalHTML = `
        <div class="toast toast-error flex-column" style="border-left-width: 6px; box-shadow: 0 0 30px rgba(255, 0, 127, 0.45); animation: scaleUp 0.4s ease;">
            <div class="explain-header" style="width: 100%; border:none; margin:0; padding-bottom:6px;">
                <span style="font-weight: 700; color: var(--danger-color); display:flex; align-items:center; gap:8px;">
                    <i class="fa-solid fa-triangle-exclamation"></i> DEPLOYED ML THREAT INTRUSION
                </span>
                <span class="badge badge-danger">Critical Threat</span>
            </div>
            <p style="font-size: 0.85rem; line-height: 1.4; color: var(--text-primary); margin-top:8px;">
                ${data.message}
            </p>
        </div>
    `;
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.innerHTML = modalHTML;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(-20px)';
        toast.style.transition = 'all 0.5s ease';
        setTimeout(() => toast.remove(), 500);
    }, 6000);
}

// --- 3. Explainable Risk Decision Sandbox Trace ---
function showDecisionTrace(newBalance, riskLevel, riskScore, reasons, completed, otpPassed, facePassed, failMessage = "") {
    const box = document.getElementById('explainOutput');
    if (!box) return;
    
    const reasonsHTML = reasons.map(r => `<li><i class="fa-solid fa-triangle-exclamation" style="color: var(--warning-color);"></i> ${r}</li>`).join('');
    
    const traceHTML = `
        <div class="explain-header">
            <span style="font-weight: 700;"><i class="fa-solid fa-fingerprint"></i> Explainable Security trace</span>
            <span class="badge ${riskLevel === 'LOW' ? 'badge-success' : riskLevel === 'MEDIUM' ? 'badge-warning' : 'badge-danger'}">Risk Score: ${riskScore}/100 (${riskLevel})</span>
        </div>
        <div style="font-size: 0.85rem; margin-top: 10px;">
            <h4 style="margin-bottom: 5px; color: var(--text-primary);">Security Risk Signals Evaluated:</h4>
            <ul style="list-style: none; padding-left: 5px; margin-bottom: 12px; line-height: 1.5;">
                ${reasonsHTML}
            </ul>
            
            <h4 style="margin-bottom: 5px; color: var(--text-primary);">Adaptive Authentication Ledger:</h4>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px;">
                <div style="background: rgba(255,255,255,0.05); padding: 8px; border-radius: 6px; text-align: center;">
                    <span style="font-size: 0.75rem; color: var(--text-secondary);">Factor 2: Mobile OTP</span>
                    <div style="font-weight: 700; color: ${otpPassed ? 'var(--success-color)' : 'var(--danger-color)'};">
                        ${otpPassed ? '<i class="fa-solid fa-circle-check"></i> PASSED' : '<i class="fa-solid fa-circle-xmark"></i> NOT EXECUTED'}
                    </div>
                </div>
                <div style="background: rgba(255,255,255,0.05); padding: 8px; border-radius: 6px; text-align: center;">
                    <span style="font-size: 0.75rem; color: var(--text-secondary);">Factor 3: Liveness & Face</span>
                    <div style="font-weight: 700; color: ${facePassed ? 'var(--success-color)' : 'var(--danger-color)'};">
                        ${facePassed ? '<i class="fa-solid fa-circle-check"></i> PASSED' : '<i class="fa-solid fa-circle-xmark"></i> NOT EXECUTED'}
                    </div>
                </div>
            </div>
            
            <div style="border-top: 1px dashed rgba(255,255,255,0.1); padding-top: 8px; display: flex; justify-content: space-between; align-items: center;">
                <span class="text-muted">Final Decision:</span>
                <strong style="color: ${completed ? 'var(--success-color)' : 'var(--danger-color)'};">
                    ${completed ? 'APPROVED & COMPLETED' : `REJECTED/HELD (${failMessage || 'Biometric Lock Failed'})`}
                </strong>
            </div>
        </div>
    `;
    box.innerHTML = traceHTML;
}


// --- 4. Explainability Sandbox Interactive Simulator ---
function runSandboxSimulation() {
    const ttype = document.getElementById('sbType').value;
    const amount = parseFloat(document.getElementById('sbAmount').value || 0);
    const oldbalanceOrig = parseFloat(document.getElementById('sbOldOrig').value || 0);
    const newbalanceOrig = oldbalanceOrig - amount;
    const oldbalanceDest = parseFloat(document.getElementById('sbOldDest').value || 0);
    const newbalanceDest = oldbalanceDest + amount;

    fetch('/api/model/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            type: ttype,
            amount: amount,
            oldbalanceOrig: oldbalanceOrig,
            newbalanceOrig: newbalanceOrig,
            oldbalanceDest: oldbalanceDest,
            newbalanceDest: newbalanceDest
        })
    })
    .then(res => res.json())
    .then(data => {
        const probText = document.getElementById('sbProbability');
        const badge = document.getElementById('sbDecisionBadge');
        const reasonsList = document.getElementById('sbReasonsList');

        probText.innerText = `${data.probability}%`;
        reasonsList.innerHTML = '';
        
        if (data.is_fraud) {
            badge.innerText = 'Suspicious Block Trigger';
            badge.className = 'badge badge-danger';
        } else {
            badge.innerText = 'Safe Baseline Vector';
            badge.className = 'badge badge-success';
        }

        data.reasons.forEach(r => {
            const li = document.createElement('li');
            li.innerHTML = `<i class="fa-solid fa-angles-right text-primary"></i> ${r}`;
            reasonsList.appendChild(li);
        });
    });
}


// --- 5. Auditor Dashboard Loader ---
function loadAdminData() {
    // 1. Fetch KPI metrics stats
    fetch('/api/admin/stats')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const s = data.stats;
                document.getElementById('kpiUsers').innerText = s.total_users;
                document.getElementById('kpiVolume').innerText = `₹${s.total_normal_value.toLocaleString()}`;
                document.getElementById('kpiBlocked').innerText = s.total_blocked_attempts;
                document.getElementById('kpiFraudRate').innerText = `${s.fraud_rate.toFixed(2)}%`;
                document.getElementById('kpiAvgTx').innerText = `₹${s.average_tx_amount.toLocaleString()}`;
                
                // Update Admin Bio summaries
                document.getElementById('adminBioEnrolledCount').innerText = s.biometrics.enrolled_users;
                document.getElementById('adminBioMismatchesCount').innerText = s.biometrics.face_mismatches + s.biometrics.liveness_failures;
                
                // Load charts
                renderVolumeChart(s.daily_trends);
                loadEnterpriseAdminStats();
            }
        });

    // 2. Fetch User Ledgers
    fetch('/api/admin/users')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const list = document.getElementById('adminUsersList');
                list.innerHTML = '';
                
                data.users.forEach(user => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${user.id}</td>
                        <td class="font-bold">${user.username}</td>
                        <td>${user.name}</td>
                        <td>${user.email}</td>
                        <td>${user.phone}</td>
                        <td>${user.sex}</td>
                        <td class="font-heading font-bold text-success">₹${user.balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
                    `;
                    list.appendChild(row);
                });
            }
        });

    // 3. Fetch Master Transactions Log
    fetch('/api/admin/transactions')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const list = document.getElementById('adminTransactionsList');
                list.innerHTML = '';
                
                data.transactions.forEach(tx => {
                    const isFraudPred = tx.is_fraud ? '<span class="badge badge-danger">Suspicious</span>' : '<span class="badge badge-success">Normal</span>';
                    const statusBadge = tx.status === 'APPROVED' ? `<span class="badge badge-success">Approved</span>` : `<span class="badge badge-danger">Blocked</span>`;
                    
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${formatDate(tx.timestamp)}</td>
                        <td class="font-bold">${tx.sender}</td>
                        <td class="font-bold">${tx.receiver}</td>
                        <td>${tx.type}</td>
                        <td class="font-heading font-bold">₹${tx.amount.toLocaleString()}</td>
                        <td>${statusBadge}</td>
                        <td>${isFraudPred}</td>
                        <td>
                            <button class="btn btn-outline btn-sm" onclick="openXaiTrace(${tx.id})" style="padding: 2px 6px; font-size: 0.72rem; border-radius: 4px;">
                                <i class="fa-solid fa-brain"></i> XAI
                            </button>
                        </td>
                    `;
                    list.appendChild(row);
                });
            }
        });
        
    // 4. Fetch Biometric Security Event audit logs
    fetch('/api/admin/biometric_events')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const list = document.getElementById('adminBiometricEventsList');
                list.innerHTML = '';
                
                if (data.events.length === 0) {
                    list.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No biometric security threat alerts recorded.</td></tr>`;
                    return;
                }
                
                data.events.forEach(e => {
                    const sevBadge = e.severity === 'HIGH' ? '<span class="badge badge-danger">High</span>' : e.severity === 'MEDIUM' ? '<span class="badge badge-warning">Medium</span>' : '<span class="badge badge-success">Low</span>';
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${formatDate(e.created_at)}</td>
                        <td class="font-bold">${e.username}</td>
                        <td><span style="font-weight:700;">${e.event_type}</span></td>
                        <td>${sevBadge}</td>
                        <td class="text-muted" style="font-size:0.8rem;">${e.metadata}</td>
                    `;
                    list.appendChild(row);
                });
            }
        });
}

function triggerModelRetrain() {
    showToast('Retraining Model', 'Initiating machine learning retrain pipeline...', 'info');
    fetch('/api/model/retrain', { method: 'POST' })
        .then(async res => {
            const data = await res.json();
            if (res.status === 200 && data.status === 'success') {
                showToast('Retrain Success', data.message, 'success');
                loadAdminData();
            } else {
                showToast('Retrain Failed', data.message || 'Error occurred.', 'error');
            }
        })
        .catch(() => showToast('Network Error', 'Retrain pipeline failed.', 'error'));
}

// Chart rendering
let volumeChartInstance = null;
function renderVolumeChart(trends) {
    const ctx = document.getElementById('volumeTrendChart');
    if (!ctx) return;
    
    const labels = trends.map(t => t.date);
    const data = trends.map(t => t.amount);
    
    if (volumeChartInstance) {
        volumeChartInstance.destroy();
    }
    
    volumeChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Daily Transaction Volume (₹)',
                data: data,
                borderColor: '#00f5d4',
                backgroundColor: 'rgba(0, 245, 212, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#b5b2bc' } },
                x: { grid: { display: false }, ticks: { color: '#b5b2bc' } }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}


// --- 6. Utilities ---
function showToast(title, message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = '<i class="fa-solid fa-circle-info"></i>';
    if (type === 'success') icon = '<i class="fa-solid fa-circle-check"></i>';
    if (type === 'error') icon = '<i class="fa-solid fa-triangle-exclamation"></i>';
    
    toast.innerHTML = `
        <span class="toast-icon">${icon}</span>
        <div class="toast-body">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(50px)';
        toast.style.transition = 'all 0.4s ease';
        setTimeout(() => toast.remove(), 400);
    }, 4500);
}

function formatDate(dateStr) {
    if (!dateStr) return '';
    try {
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-IN', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch {
        return dateStr;
    }
}


// ==========================================
// --- WebSocket & Explainable AI (XAI) Methods ---
// ==========================================

function initSocket() {
    try {
        socket = io({
            transports: ['websocket', 'polling'],
            reconnectionAttempts: 5,
            timeout: 5000
        });
        
        socket.on('connect', () => {
            console.log("WebSocket connected.");
            if (currentUser && currentUser.is_admin) {
                socket.emit('join_admin');
            }
            const badge = document.getElementById('liveRiskModeBadge');
            if (badge) {
                badge.className = 'live-badge badge-provisional';
                badge.innerText = 'Live Estimate';
            }
        });
        
        socket.on('disconnect', () => {
            console.log("WebSocket disconnected.");
            handleSocketFallback();
        });
        
        socket.on('connect_error', () => {
            console.log("WebSocket connection error.");
            handleSocketFallback();
        });
        
        socket.on('live_risk_result', (data) => {
            if (data.status === 'success') {
                updateLiveRiskUI(data.score, data.level, data.reasons);
            }
        });
        
        socket.on('new_transaction', (tx) => {
            if (currentUser && currentUser.is_admin) {
                handleNewTransactionAlert(tx);
            }
        });
    } catch (err) {
        console.error("SocketIO initialization failed:", err);
        handleSocketFallback();
    }
}

function handleSocketFallback() {
    const badge = document.getElementById('liveRiskModeBadge');
    if (badge) {
        badge.className = 'live-badge badge-fallback';
        badge.innerText = 'Manual Check';
    }
}

function initLiveRiskMeter() {
    const receiverInput = document.getElementById('txReceiver');
    const amountInput = document.getElementById('txAmount');
    const typeSelect = document.getElementById('txType');
    
    if (!receiverInput || !amountInput || !typeSelect) return;
    
    const triggerCheck = () => {
        clearTimeout(liveRiskTimeout);
        liveRiskTimeout = setTimeout(runLiveRiskCheck, 400);
    };
    
    receiverInput.addEventListener('input', triggerCheck);
    amountInput.addEventListener('input', triggerCheck);
    typeSelect.addEventListener('change', triggerCheck);
    
    // Clicking card runs check if socket fell back
    const card = document.getElementById('liveRiskCard');
    if (card) {
        card.addEventListener('click', runLiveRiskCheck);
    }
}

function runLiveRiskCheck() {
    const receiver = document.getElementById('txReceiver').value.trim();
    const amount = parseFloat(document.getElementById('txAmount').value) || 0;
    const type = document.getElementById('txType').value;
    const card = document.getElementById('liveRiskCard');
    
    if (!receiver || amount <= 0) {
        if (card) card.style.display = 'none';
        return;
    }
    
    if (card) card.style.display = 'block';
    
    const payload = { receiver, amount, type };
    
    if (socket && socket.connected) {
        socket.emit('live_risk_check', payload);
    } else {
        fetch('/api/transfer/live_risk_preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                updateLiveRiskUI(data.score, data.level, data.reasons);
            }
        })
        .catch(err => console.error("Provisional risk check fallback failed:", err));
    }
}

function updateLiveRiskUI(score, level, reasons) {
    const bar = document.getElementById('liveRiskBar');
    const val = document.getElementById('liveRiskVal');
    const label = document.getElementById('liveRiskLevel');
    const list = document.getElementById('liveRiskSignals');
    
    if (!bar || !val || !label || !list) return;
    
    val.innerText = score + '/100';
    bar.style.width = score + '%';
    
    bar.className = 'live-risk-bar';
    label.className = 'live-risk-level-label';
    
    if (level === 'LOW') {
        bar.classList.add('bg-success');
        label.classList.add('text-success');
        label.innerText = 'LOW RISK (Auto Approve)';
    } else if (level === 'MEDIUM') {
        bar.classList.add('bg-warning');
        label.classList.add('text-warning');
        label.innerText = 'MEDIUM RISK (OTP Required)';
    } else if (level === 'HIGH') {
        bar.classList.add('bg-danger-orange');
        label.classList.add('text-warning');
        label.innerText = 'HIGH RISK (MFA Required)';
    } else {
        bar.classList.add('bg-danger');
        label.classList.add('text-danger');
        label.innerText = 'CRITICAL RISK (WILL BLOCK)';
    }
    
    list.innerHTML = '';
    if (reasons && reasons.length > 0) {
        reasons.forEach(r => {
            const div = document.createElement('div');
            div.className = 'live-signal-item';
            
            let icon = 'fa-circle-info';
            if (r.includes('Matches synthetic') || r.includes('Velocity') || r.includes('Biometric')) {
                icon = 'fa-circle-exclamation';
            } else if (r.includes('Account Emptying') || r.includes('Critical Volume')) {
                icon = 'fa-triangle-exclamation';
            }
            
            div.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${r}</span>`;
            list.appendChild(div);
        });
    } else {
        list.innerHTML = `<div class="live-signal-item"><i class="fa-solid fa-circle-check"></i> No critical anomalies flagged.</div>`;
    }
}

function handleNewTransactionAlert(tx) {
    if (isFeedPaused) return;
    
    liveFeedData.unshift(tx);
    if (liveFeedData.length > 50) {
        liveFeedData.pop();
    }
    
    renderLiveFeedTable();
    updateLiveFeedSummary();
}

function renderLiveFeedTable() {
    const tbody = document.getElementById('liveFraudFeedBody');
    if (!tbody) return;
    
    const filterUserVal = document.getElementById('filterUser').value.trim().toLowerCase();
    const filterRiskVal = document.getElementById('filterRisk').value;
    const filterOutcomeVal = document.getElementById('filterOutcome').value;
    
    tbody.innerHTML = '';
    
    const filtered = liveFeedData.filter(tx => {
        if (filterUserVal) {
            const senderMatch = tx.sender.toLowerCase().includes(filterUserVal);
            const recMatch = tx.receiver.toLowerCase().includes(filterUserVal);
            if (!senderMatch && !recMatch) return false;
        }
        if (filterRiskVal !== 'ALL') {
            if (tx.risk_level !== filterRiskVal) return false;
        }
        if (filterOutcomeVal !== 'ALL') {
            if (tx.status !== filterOutcomeVal) return false;
        }
        return true;
    });
    
    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No transactions matching active filter rules.</td></tr>`;
        return;
    }
    
    filtered.forEach(tx => {
        const tr = document.createElement('tr');
        
        let rowClass = 'feed-row-low';
        let badgeClass = 'badge-low';
        if (tx.risk_level === 'MEDIUM') {
            rowClass = 'feed-row-medium';
            badgeClass = 'badge-medium';
        } else if (tx.risk_level === 'HIGH') {
            rowClass = 'feed-row-high';
            badgeClass = 'badge-high';
        } else if (tx.risk_level === 'CRITICAL') {
            rowClass = 'feed-row-critical';
            badgeClass = 'badge-danger';
        }
        
        tr.className = rowClass;
        const mainReason = tx.reasons && tx.reasons.length > 0 ? tx.reasons[0] : 'None';
        
        // Dynamic XAI trace button if ID exists
        const txId = tx.id || '';
        const actionCell = txId ? 
            `<button class="btn btn-outline btn-sm" onclick="openXaiTrace(${txId})" style="padding: 2px 6px; font-size: 0.72rem; border-radius: 4px;"><i class="fa-solid fa-brain"></i> XAI Trace</button>` :
            `<span class="text-muted">Provisional</span>`;
            
        tr.innerHTML = `
            <td>${tx.timestamp}</td>
            <td><code style="font-size: 0.8rem; color: #fff;">${tx.sender}</code></td>
            <td><code style="font-size: 0.8rem; color: #fff;">${tx.receiver}</code></td>
            <td style="font-weight: 600;">₹${tx.amount.toLocaleString()}</td>
            <td><span class="badge ${badgeClass}">${tx.risk_score}/100 ${tx.risk_level}</span></td>
            <td>
                <span class="badge ${tx.status === 'APPROVED' ? 'badge-low' : 'badge-danger'}">
                    ${tx.status}
                </span>
            </td>
            <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.75rem;" title="${tx.reasons ? tx.reasons.join(', ') : ''}">
                ${mainReason}
            </td>
            <td>${actionCell}</td>
        `;
        tbody.appendChild(tr);
    });
}

function updateLiveFeedSummary() {
    document.getElementById('feedTotalTx').innerText = liveFeedData.length;
    
    let totalScore = 0;
    let blockedCount = 0;
    let lowCount = 0;
    let medCount = 0;
    let highCount = 0;
    
    liveFeedData.forEach(tx => {
        totalScore += tx.risk_score;
        if (tx.status === 'BLOCKED') blockedCount++;
        if (tx.risk_level === 'LOW') lowCount++;
        else if (tx.risk_level === 'MEDIUM') medCount++;
        else if (tx.risk_level === 'HIGH' || tx.risk_level === 'CRITICAL') highCount++;
    });
    
    const avg = liveFeedData.length > 0 ? Math.round(totalScore / liveFeedData.length) : 0;
    document.getElementById('feedAvgRisk').innerText = avg + '/100';
    document.getElementById('feedBlockedCount').innerText = blockedCount;
    document.getElementById('feedCountLow').innerText = lowCount;
    document.getElementById('feedCountMedium').innerText = medCount;
    document.getElementById('feedCountHigh').innerText = highCount;
}

function openXaiTrace(txId) {
    fetch(`/api/transaction/${txId}/trace`)
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const tx = data.transaction;
                const trace = data.trace;
                
                document.getElementById('xaiTxId').innerText = '#' + tx.id;
                document.getElementById('xaiTxTimestamp').innerText = formatDate(tx.timestamp);
                document.getElementById('xaiTxSender').innerText = tx.sender;
                document.getElementById('xaiTxReceiver').innerText = tx.receiver;
                document.getElementById('xaiTxAmount').innerText = '₹' + tx.amount.toLocaleString('en-IN', { minimumFractionDigits: 2 });
                
                document.getElementById('xaiRiskScore').innerText = trace.risk_score;
                
                // Render enriched XAI metrics
                document.getElementById('xaiConfidence').innerText = (trace.confidence || 95) + '%';
                document.getElementById('xaiRecommendation').innerText = trace.recommendation || 'Approved';
                
                const policiesList = document.getElementById('xaiPoliciesList');
                if (policiesList) {
                    policiesList.innerHTML = '';
                    const policies = trace.triggered_policies || ["POL-000: Default Compliance Verification"];
                    policies.forEach(p => {
                        const li = document.createElement('li');
                        li.innerText = p;
                        policiesList.appendChild(li);
                    });
                }
                
                const levelEl = document.getElementById('xaiRiskLevel');
                levelEl.innerText = trace.risk_level;
                levelEl.className = 'badge';
                if (trace.risk_level === 'LOW') levelEl.classList.add('badge-low');
                else if (trace.risk_level === 'MEDIUM') levelEl.classList.add('badge-medium');
                else if (trace.risk_level === 'HIGH') levelEl.classList.add('badge-high');
                else levelEl.classList.add('badge-danger');
                
                const bd = trace.breakdown || {};
                const breakdownList = document.getElementById('xaiBreakdownList');
                breakdownList.innerHTML = '';
                
                const addBreakdownRow = (label, val) => {
                    const div = document.createElement('div');
                    div.style.display = 'flex';
                    div.style.justify = 'space-between';
                    div.style.borderBottom = '1px solid rgba(255,255,255,0.04)';
                    div.style.padding = '4px 0';
                    div.innerHTML = `<span class="text-muted">${label}:</span> <strong style="color: #fff;">+${val} pts</strong>`;
                    breakdownList.appendChild(div);
                };
                
                addBreakdownRow("Base Risk Factor", bd.base_points || 10);
                addBreakdownRow("Transaction Volume Points", bd.amount_points || 0);
                addBreakdownRow("Account Emptying Points", bd.empty_account_points || 0);
                addBreakdownRow("New Beneficiary Points", bd.new_recipient_points || 0);
                addBreakdownRow("Random Forest Model Points", bd.ml_model_points || 0);
                addBreakdownRow("Velocity Anomaly Points", bd.velocity_points || 0);
                addBreakdownRow("Recent Biometric Failures", bd.biometric_points || 0);
                
                const reasonsList = document.getElementById('xaiReasonsList');
                reasonsList.innerHTML = '';
                if (trace.reasons && trace.reasons.length > 0) {
                    trace.reasons.forEach(r => {
                        const li = document.createElement('li');
                        li.innerText = r;
                        reasonsList.appendChild(li);
                    });
                } else {
                    reasonsList.innerHTML = '<li>No indicators flagged.</li>';
                }
                
                const fiChart = document.getElementById('xaiFeaturesChart');
                fiChart.innerHTML = '';
                const fi = trace.feature_importances || {};
                
                const formatFeatureName = (name) => {
                    if (name === 'oldbalanceOrig') return 'Sender Balance (Prev)';
                    if (name === 'newbalanceOrig') return 'Sender Balance (New)';
                    if (name === 'oldbalanceDest') return 'Receiver Balance (Prev)';
                    if (name === 'newbalanceDest') return 'Receiver Balance (New)';
                    if (name === 'amount') return 'Transfer Amount';
                    if (name.includes('type_')) return `Type: ${name.split('_')[1]}`;
                    return name;
                };
                
                const sortedFeatures = Object.entries(fi).sort((a, b) => b[1] - a[1]);
                if (sortedFeatures.length > 0) {
                    sortedFeatures.forEach(([name, val]) => {
                        const row = document.createElement('div');
                        row.style.margin = '4px 0';
                        const pct = (val * 100).toFixed(1);
                        row.innerHTML = `
                            <div style="display: flex; justify-content: space-between; font-size: 0.72rem; margin-bottom: 2px;">
                                <span class="text-muted">${formatFeatureName(name)}</span>
                                <strong>${pct}%</strong>
                            </div>
                            <div class="xai-bar-container" style="background: rgba(255,255,255,0.06); height: 6px; border-radius: 3px; overflow: hidden; margin-bottom: 6px;">
                                <div style="background: var(--accent-color); height: 100%; width: ${pct}%;"></div>
                            </div>
                        `;
                        fiChart.appendChild(row);
                    });
                } else {
                    fiChart.innerHTML = '<div class="text-muted text-center">No model weights available.</div>';
                }
                
                const reqs = trace.auth_required || [];
                const cmps = trace.auth_completed || [];
                
                const updateChecklistItem = (elId, code) => {
                    const el = document.getElementById(elId);
                    if (!el) return;
                    
                    const isReq = reqs.includes(code);
                    const isCmp = cmps.includes(code);
                    
                    if (!isReq) {
                        el.innerHTML = `<i class="fa-solid fa-circle-minus text-muted"></i> <span class="text-muted">${el.innerText.split(' ').slice(1).join(' ').replace(/\(.*\)/g, '')} (Not Required)</span>`;
                    } else if (isCmp) {
                        el.innerHTML = `<i class="fa-solid fa-circle-check text-success"></i> <strong style="color: #fff;">${el.innerText.split(' ').slice(1).join(' ').replace(/\(.*\)/g, '')} (Completed)</strong>`;
                    } else {
                        el.innerHTML = `<i class="fa-solid fa-circle-xmark text-danger"></i> <span style="color: var(--text-secondary);">${el.innerText.split(' ').slice(1).join(' ').replace(/\(.*\)/g, '')} (Failed / Required)</span>`;
                    }
                };
                
                updateChecklistItem('xaiCheckOtp', 'otp');
                
                const hasFaceReq = reqs.includes('face');
                const hasFaceCmp = cmps.includes('face');
                
                const faceEl = document.getElementById('xaiCheckFace');
                const livenessEl = document.getElementById('xaiCheckLiveness');
                
                if (hasFaceReq) {
                    if (hasFaceCmp) {
                        livenessEl.innerHTML = `<i class="fa-solid fa-circle-check text-success"></i> <strong style="color: #fff;">Active Head-Rotation Liveness (Completed)</strong>`;
                        faceEl.innerHTML = `<i class="fa-solid fa-circle-check text-success"></i> <strong style="color: #fff;">SFace 1:1 Cosine Match (Completed)</strong>`;
                    } else {
                        livenessEl.innerHTML = `<i class="fa-solid fa-circle-xmark text-danger"></i> <span style="color: var(--text-secondary);">Active Head-Rotation Liveness (Failed)</span>`;
                        faceEl.innerHTML = `<i class="fa-solid fa-circle-xmark text-danger"></i> <span style="color: var(--text-secondary);">SFace 1:1 Cosine Match (Failed)</span>`;
                    }
                } else {
                    livenessEl.innerHTML = `<i class="fa-solid fa-circle-minus text-muted"></i> <span class="text-muted">Active Head-Rotation Liveness (Not Required)</span>`;
                    faceEl.innerHTML = `<i class="fa-solid fa-circle-minus text-muted"></i> <span class="text-muted">SFace 1:1 Cosine Match (Not Required)</span>`;
                }
                
                document.getElementById('xaiTraceModal').classList.remove('hidden');
            } else {
                showToast('Trace Error', data.message, 'error');
            }
        })
        .catch(err => {
            console.error("XAI trace fetch error:", err);
            showToast('Network Error', 'Failed to fetch XAI threat report.', 'error');
        });
}

function closeXaiTraceModal() {
    document.getElementById('xaiTraceModal').classList.add('hidden');
}


// --- Model Metrics and Admin Review Helpers ---
function loadModelMetrics() {
    fetch('/api/model/metrics')
        .then(res => res.json())
        .then(data => {
            const mAcc = document.getElementById('modelAccuracy');
            const mPrec = document.getElementById('modelPrecision');
            const mRec = document.getElementById('modelRecall');
            const mF1 = document.getElementById('modelF1');
            const mSamples = document.getElementById('modelSamples');
            
            const bAcc = document.getElementById('barAccuracy');
            const bPrec = document.getElementById('barPrecision');
            const bRec = document.getElementById('barRecall');
            const bF1 = document.getElementById('barF1');
            
            const tn = document.getElementById('matrixTN');
            const fp = document.getElementById('matrixFP');
            const fn = document.getElementById('matrixFN');
            const tp = document.getElementById('matrixTP');
            
            if (data.status === 'active') {
                const accStr = (data.accuracy * 100).toFixed(2) + '%';
                const precStr = (data.precision * 100).toFixed(2) + '%';
                const recStr = (data.recall * 100).toFixed(2) + '%';
                const f1Str = (data.f1_score * 100).toFixed(2) + '%';
                
                if (mAcc) { mAcc.innerText = accStr; bAcc.style.width = accStr; }
                if (mPrec) { mPrec.innerText = precStr; bPrec.style.width = precStr; }
                if (mRec) { mRec.innerText = recStr; bRec.style.width = recStr; }
                if (mF1) { mF1.innerText = f1Str; bF1.style.width = f1Str; }
                if (mSamples) mSamples.innerText = data.n_samples.toLocaleString();
                
                if (tn) tn.innerText = data.confusion_matrix[0][0];
                if (fp) fp.innerText = data.confusion_matrix[0][1];
                if (fn) fn.innerText = data.confusion_matrix[1][0];
                if (tp) tp.innerText = data.confusion_matrix[1][1];
            } else {
                const na = 'Unavailable';
                if (mAcc) mAcc.innerText = na;
                if (mPrec) mPrec.innerText = na;
                if (mRec) mRec.innerText = na;
                if (mF1) mF1.innerText = na;
                if (mSamples) mSamples.innerText = na;
            }
        })
        .catch(() => {
            const na = 'Unavailable';
            const mAcc = document.getElementById('modelAccuracy');
            if (mAcc) mAcc.innerText = na;
            const mPrec = document.getElementById('modelPrecision');
            if (mPrec) mPrec.innerText = na;
            const mRec = document.getElementById('modelRecall');
            if (mRec) mRec.innerText = na;
            const mF1 = document.getElementById('modelF1');
            if (mF1) mF1.innerText = na;
            const mSamples = document.getElementById('modelSamples');
            if (mSamples) mSamples.innerText = na;
        });
}

function loadAdminReviewQueue() {
    fetch('/api/admin/reviews')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const tbody = document.getElementById('adminReviewQueueBody');
                if (!tbody) return;
                tbody.innerHTML = '';
                
                if (data.reviews.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No transactions pending review.</td></tr>';
                    return;
                }
                
                data.reviews.forEach(rev => {
                    const row = document.createElement('tr');
                    
                    const tokenTrunc = rev.token.substring(0, 8) + '...';
                    const reasonsStr = rev.reasons.join(', ');
                    
                    row.innerHTML = `
                        <td title="${rev.token}">${tokenTrunc}</td>
                        <td>${rev.user_id}</td>
                        <td>${rev.receiver}</td>
                        <td><span class="badge">${rev.ttype}</span></td>
                        <td>?${parseFloat(rev.amount).toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})}</td>
                        <td><span class="badge badge-danger">${rev.risk_score} (${rev.risk_level})</span></td>
                        <td class="text-muted" style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${reasonsStr}">${reasonsStr}</td>
                        <td>
                            <div style="display: flex; gap: 5px;">
                                <button class="btn btn-xs btn-success" onclick="handleReviewAction('${rev.token}', 'APPROVE')">Approve</button>
                                <button class="btn btn-xs btn-danger" onclick="handleReviewAction('${rev.token}', 'REJECT')">Reject</button>
                            </div>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            }
        });
}

function handleReviewAction(token, action) {
    const reason = prompt(`Enter reason for ${action.toLowerCase()}ing this transaction:`);
    if (reason === null) return; // cancelled
    
    fetch('/api/admin/review/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ transaction_token: token, action: action, reason: reason })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            showToast('Review Complete', data.message, 'success');
            loadAdminReviewQueue();
            loadAdminData();
        } else {
            showToast('Review Error', data.message, 'error');
        }
    })
    .catch(() => showToast('Network Error', 'Could not submit review decision.', 'error'));
}


// ==========================================
// SMART WALLET - ADD MONEY FRONTEND WORKFLOWS
// ==========================================

let activeDepositRef = null;
let currentMfaToken = null;

function openAddMoneyModal() {
    document.getElementById('addMoneySetup').classList.remove('hidden');
    document.getElementById('addMoneySimulator').classList.add('hidden');
    document.getElementById('addMoneySuccess').classList.add('hidden');
    
    document.getElementById('depositAmount').value = '';
    document.getElementById('depositRemarks').value = '';
    document.getElementById('depositMethod').value = 'UPI';
    updateGatewayOptions();
    
    document.getElementById('addMoneyModal').classList.remove('hidden');
}

function closeAddMoneyModal() {
    document.getElementById('addMoneyModal').classList.add('hidden');
}

function setDepositAmount(amt) {
    document.getElementById('depositAmount').value = amt;
}

function quickAdd(amt) {
    openAddMoneyModal();
    setDepositAmount(amt);
}

function updateGatewayOptions() {
    const method = document.getElementById('depositMethod').value;
    const gatewaySelect = document.getElementById('depositGateway');
    gatewaySelect.innerHTML = '';
    
    let options = [];
    if (method === 'UPI') {
        options = ['Google Pay', 'PhonePe', 'Paytm', 'BHIM'];
    } else if (method === 'Debit Card' || method === 'Credit Card') {
        options = ['Visa', 'MasterCard', 'RuPay'];
    } else {
        options = ['SBI Bank', 'HDFC Bank', 'ICICI Bank', 'Axis Bank'];
    }
    
    options.forEach(opt => {
        const el = document.createElement('option');
        el.value = opt;
        el.innerText = opt;
        gatewaySelect.appendChild(el);
    });
}

let isSubmittingDeposit = false;

function startDepositVerification() {
    if (isSubmittingDeposit) return;
    
    let rawAmount = document.getElementById('depositAmount').value;
    if (typeof rawAmount === 'string') {
        rawAmount = rawAmount.replace(/[₹\s,]/g, '');
    }
    const amount = parseFloat(rawAmount);
    const method = document.getElementById('depositMethod').value;
    const gateway = document.getElementById('depositGateway').value;
    const remarks = document.getElementById('depositRemarks').value.trim();
    
    if (isNaN(amount) || amount < 100 || amount > 200000) {
        showToast('Invalid Amount', 'Transaction amount must be between ₹100 and ₹2,00,000.', 'error');
        return;
    }
    
    isSubmittingDeposit = true;

    // Use Razorpay Checkout if SDK is loaded
    if (typeof window.Razorpay === 'function') {
        initiateRazorpayPayment(amount);
        return;
    }
    
    // Hide form, show simulator screen
    document.getElementById('addMoneySetup').classList.add('hidden');
    const simulator = document.getElementById('addMoneySimulator');
    simulator.classList.remove('hidden');
    
    const statuses = ['Connecting...', 'Processing...', 'Verifying...', 'Payment Authorized'];
    let statusIdx = 0;
    document.getElementById('simulatorStatus').innerText = statuses[0];
    
    const interval = setInterval(() => {
        statusIdx++;
        if (statusIdx < statuses.length) {
            document.getElementById('simulatorStatus').innerText = statuses[statusIdx];
        } else {
            clearInterval(interval);
            // Submit to initiate API
            submitDepositInitiate(amount, method, gateway, remarks);
        }
    }, 800);
}

function submitDepositInitiate(amount, method, gateway, remarks) {
    fetch('/api/add-money/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount, method, gateway, remarks })
    })
    .then(async res => {
        isSubmittingDeposit = false;
        const data = await res.json();
        document.getElementById('addMoneySimulator').classList.add('hidden');
        
        if (res.status === 200 && data.status === 'success') {
            // Success view
            activeDepositRef = data.reference_id;
            document.getElementById('successDepositAmount').innerText = amount.toLocaleString('en-US', { minimumFractionDigits: 2 });
            document.getElementById('successDepositRef').innerText = data.reference_id;
            document.getElementById('successDepositGateway').innerText = gateway;
            document.getElementById('successDepositMethod').innerText = method;
            
            // Reload user details & balance
            loadDashboardData();
            
            // Update success balance
            setTimeout(() => {
                document.getElementById('successDepositBalance').innerText = currentUser.balance.toLocaleString('en-US', { minimumFractionDigits: 2 });
            }, 500);
            
            document.getElementById('addMoneySuccess').classList.remove('hidden');
            showToast('Deposit Complete', 'Money added to your Smart Wallet successfully!', 'success');
        } 
        else if (data.status === 'verification_required') {
            // Trigger OTP or Biometric check
            closeAddMoneyModal();
            currentMfaToken = data.reference_id;
            
            if (data.face_required) {
                showToast('MFA Required', 'Please complete OTP and Biometric verification.', 'warning');
                openMfaModal(data.reference_id, true);
            } else {
                showToast('MFA Required', 'Please enter the verification code sent to your email.', 'warning');
                openMfaModal(data.reference_id, false);
            }
        } 
        else if (data.status === 'pending_review') {
            closeAddMoneyModal();
            showToast('Held for Review', 'Deposit held for administrative review due to CRITICAL security score.', 'warning');
            loadDashboardData();
        } 
        else {
            showToast('Deposit Failed', data.message || 'Payment initiation failed.', 'error');
            openAddMoneyModal();
        }
    })
    .catch(err => {
        isSubmittingDeposit = false;
        document.getElementById('addMoneySimulator').classList.add('hidden');
        showToast('Connection Error', 'Failed to communicate with billing portal.', 'error');
        openAddMoneyModal();
    });
}

function downloadDepositReceipt() {
    if (!activeDepositRef) return;
    window.open(`/api/add-money/receipt/${activeDepositRef}`, '_blank');
}

function downloadDepositReceiptById(refId) {
    window.open(`/api/add-money/receipt/${refId}`, '_blank');
}

function loadWalletAnalytics() {
    fetch('/api/add-money/analytics')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                document.getElementById('walletBalance').innerText = currentUser.balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
                document.getElementById('walletToday').innerText = data.today.toLocaleString('en-US', { minimumFractionDigits: 2 });
                document.getElementById('walletMonthly').innerText = data.monthly.toLocaleString('en-US', { minimumFractionDigits: 2 });
                document.getElementById('walletLargest').innerText = data.largest.toLocaleString('en-US', { minimumFractionDigits: 2 });
                document.getElementById('walletSuccessRate').innerText = data.success_rate.toFixed(1);
            }
        })
        .catch(err => console.error("Failed to load wallet analytics", err));
}

function renderTransactions(txs) {
    const list = document.getElementById('transactionsList');
    list.innerHTML = '';
    
    if (txs.length === 0) {
        list.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No matching transactions recorded.</td></tr>`;
        return;
    }
    
    txs.forEach(tx => {
        const isDeposit = (tx.type === 'ADD_MONEY');
        const isSender = (tx.sender === currentUser.username && !isDeposit);
        const directionIcon = isDeposit ? '<i class="fa-solid fa-arrow-right-to-bracket text-success"></i>' : (isSender ? '<i class="fa-solid fa-arrow-right-from-bracket text-danger"></i>' : '<i class="fa-solid fa-arrow-right-to-bracket text-success"></i>');
        const targetName = isDeposit ? 'Smart Wallet' : (isSender ? tx.receiver : tx.sender);
        
        let statusBadge = '';
        if (tx.status === 'APPROVED' || tx.status === 'COMPLETED') {
            statusBadge = `<span class="badge badge-success">Approved</span>`;
        } else {
            statusBadge = `<span class="badge badge-danger">Blocked</span>`;
        }
        
        let traceObj = {};
        try {
            traceObj = JSON.parse(tx.decision_trace || '{}');
        } catch(e) {}
        const refId = traceObj.reference_id || `DEP-${tx.id}`;
        
        const receiptBtn = isDeposit ? `
            <button class="btn btn-accent btn-sm" onclick="downloadDepositReceiptById('${refId}')" style="padding: 2px 6px; font-size: 0.72rem; border-radius: 4px; background: #10b981; border-color: #10b981;">
                <i class="fa-solid fa-file-pdf"></i> Receipt
            </button>
        ` : '';
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${formatDate(tx.timestamp)}</td>
            <td>${tx.type}</td>
            <td>${directionIcon} ${targetName}</td>
            <td class="font-heading font-bold">${isSender ? '-' : '+'}₹${tx.amount.toLocaleString()}</td>
            <td>${statusBadge}</td>
            <td style="display: flex; gap: 4px;">
                <button class="btn btn-outline btn-sm" onclick="openXaiTrace(${tx.id})" style="padding: 2px 6px; font-size: 0.72rem; border-radius: 4px;">
                    <i class="fa-solid fa-brain"></i> Explain
                </button>
                ${receiptBtn}
            </td>
        `;
        list.appendChild(row);
    });
}

function filterTransactions() {
    const query = document.getElementById('txSearchInput').value.toLowerCase().trim();
    const typeFilter = document.getElementById('txTypeFilter').value;
    
    let filtered = allTransactions;
    
    if (typeFilter !== 'ALL') {
        filtered = filtered.filter(tx => tx.type === typeFilter);
    }
    
    if (query) {
        filtered = filtered.filter(tx => {
            const targetName = (tx.sender === currentUser.username) ? tx.receiver : tx.sender;
            let traceObj = {};
            try { traceObj = JSON.parse(tx.decision_trace || '{}'); } catch(e) {}
            const refId = traceObj.reference_id || '';
            
            return targetName.toLowerCase().includes(query) || 
                   tx.type.toLowerCase().includes(query) || 
                   refId.toLowerCase().includes(query);
        });
    }
    
    renderTransactions(filtered);
}

function exportLedger(format) {
    if (format === 'csv') {
        let csv = 'Timestamp,Type,Sender/Receiver,Amount,Status,Reference\n';
        allTransactions.forEach(tx => {
            let traceObj = {};
            try { traceObj = JSON.parse(tx.decision_trace || '{}'); } catch(e) {}
            const refId = traceObj.reference_id || `DEP-${tx.id}`;
            const targetName = (tx.sender === currentUser.username) ? tx.receiver : tx.sender;
            csv += `"${formatDate(tx.timestamp)}","${tx.type}","${targetName}","${tx.amount}","${tx.status}","${refId}"\n`;
        });
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.setAttribute('href', url);
        a.setAttribute('download', 'Transaction_Ledger.csv');
        a.click();
    } else {
        window.print();
    }
}


// ==========================================
// PHASE 1 – QR PAYMENT SYSTEM CLIENT WORKFLOWS
// ==========================================

let currentScannedToken = null;

function openQrShowModal() {
    fetch('/api/qr/token')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const container = document.getElementById("qrCanvasContainer");
                container.innerHTML = ""; // Clear
                
                // Create qrcode using QRCode.js library
                new QRCode(container, {
                    text: data.qr_token,
                    width: 180,
                    height: 180,
                    colorDark : "#0f172a",
                    colorLight : "#ffffff",
                    correctLevel : QRCode.CorrectLevel.H
                });
                
                document.getElementById("qrShowModal").classList.remove("hidden");
            } else {
                showToast("QR Error", data.message || "Failed to generate QR code.", "error");
            }
        })
        .catch(err => showToast("Network Error", "Could not fetch QR code token.", "error"));
}

function closeQrShowModal() {
    document.getElementById("qrShowModal").classList.add("hidden");
}

function downloadMyQr() {
    const img = document.getElementById("qrCanvasContainer").getElementsByTagName("img")[0];
    const canvas = document.getElementById("qrCanvasContainer").getElementsByTagName("canvas")[0];
    if (img) {
        const a = document.createElement("a");
        a.href = img.src;
        a.download = "SmartBank_QR.png";
        a.click();
    } else if (canvas) {
        const a = document.createElement("a");
        a.href = canvas.toDataURL("image/png");
        a.download = "SmartBank_QR.png";
        a.click();
    } else {
        showToast("Download Error", "QR image not ready.", "error");
    }
}

function openQrScanModal() {
    document.getElementById("qrScanResult").classList.add("hidden");
    document.getElementById("qrUploadContainer").style.display = "block";
    document.getElementById("qrFileInput").value = "";
    document.getElementById("qrScanModal").classList.remove("hidden");
}

function closeQrScanModal() {
    document.getElementById("qrScanModal").classList.add("hidden");
}

function handleQrUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.createElement("canvas");
            canvas.width = img.width;
            canvas.height = img.height;
            const ctx = canvas.getContext("2d");
            ctx.drawImage(img, 0, 0);
            const imgData = ctx.getImageData(0, 0, img.width, img.height);
            
            // Call jsQR decoder
            const code = jsQR(imgData.data, imgData.width, imgData.height);
            if (code) {
                verifyScannedToken(code.data);
            } else {
                showToast("Decoding Failed", "No valid QR code found in this image.", "error");
            }
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function verifyScannedToken(token) {
    fetch('/api/qr/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ qr_token: token })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            currentScannedToken = token;
            document.getElementById("qrRecName").innerText = `${data.firstname} ${data.lastname}`;
            document.getElementById("qrRecUsername").innerText = data.username;
            
            document.getElementById("qrUploadContainer").style.display = "none";
            document.getElementById("qrScanResult").classList.remove("hidden");
            showToast("Verified", "Recipient successfully verified.", "success");
        } else {
            showToast("Verification Failed", data.message || "Invalid or expired QR token.", "error");
        }
    })
    .catch(err => showToast("Network Error", "Failed to verify scanned QR code.", "error"));
}

function executeQrPayment() {
    const receiver = document.getElementById("qrRecUsername").innerText;
    const amount = parseFloat(document.getElementById("qrAmount").value);
    const remarks = document.getElementById("qrRemarks").value.trim();
    const qr_token = currentScannedToken;
    
    if (isNaN(amount) || amount <= 0) {
        showToast("Invalid Amount", "Please enter a valid transfer amount.", "error");
        return;
    }
    
    fetch('/api/transfer/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            receiver: receiver,
            amount: amount,
            type: 'QR_PAYMENT',
            qr_token: qr_token,
            remarks: remarks
        })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            showToast("Payment Successful", "Payment completed successfully!", "success");
            closeQrScanModal();
            loadDashboardData();
        } else if (data.status === 'verification_required') {
            closeQrScanModal();
            if (data.face_required) {
                openMfaModal(data.token, true);
            } else {
                openMfaModal(data.token, false);
            }
        } else if (data.status === 'pending_review') {
            closeQrScanModal();
            showToast("Held for Review", "Transaction flagged for administrative review.", "warning");
            loadDashboardData();
        } else {
            showToast("Payment Error", data.message || "Failed to process QR payment.", "error");
        }
    })
    .catch(err => {
        showToast("Network Error", "Failed to initiate payment.", "error");
    });
}


// ==========================================
// PHASE 2 – BENEFICIARY CLIENT WORKFLOWS
// ==========================================

let beneficiaryCurrentPage = 1;
let beneficiaryTotalRows = 0;

function openBeneficiariesModal() {
    beneficiaryCurrentPage = 1;
    loadBeneficiaryList();
    document.getElementById("beneficiariesModal").classList.remove("hidden");
}

function closeBeneficiariesModal() {
    document.getElementById("beneficiariesModal").classList.add("hidden");
}

function openAddBeneficiaryModal() {
    document.getElementById("addBUsername").value = "";
    document.getElementById("addBNickname").value = "";
    document.getElementById("addBeneficiaryModal").classList.remove("hidden");
}

function closeAddBeneficiaryModal() {
    document.getElementById("addBeneficiaryModal").classList.add("hidden");
}

function loadBeneficiaryList() {
    const search = document.getElementById("bSearchInput").value.trim();
    const sort = document.getElementById("bSortSelect").value;
    
    fetch(`/api/beneficiaries?search=${encodeURIComponent(search)}&sort=${sort}&page=${beneficiaryCurrentPage}&per_page=5`)
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const tbody = document.getElementById("beneficiaryTableBody");
                tbody.innerHTML = "";
                
                if (data.beneficiaries.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="3" style="text-align: center;" class="text-muted">No beneficiaries found.</td></tr>`;
                }
                
                data.beneficiaries.forEach(b => {
                    const favIcon = b.is_favorite ? 'fa-star text-accent' : 'fa-star-o';
                    const favClass = b.is_favorite ? 'fa-solid fa-star' : 'fa-regular fa-star';
                    const favStyle = b.is_favorite ? 'color: #e9d502;' : 'color: rgba(255,255,255,0.4);';
                    
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>
                            <div><strong>${escapeHtml(b.nickname)}</strong></div>
                            <div class="text-muted" style="font-size: 0.8rem;">@${escapeHtml(b.beneficiary_username)}</div>
                        </td>
                        <td>
                            <div>${b.transfer_count} txs</div>
                            <div class="text-muted" style="font-size: 0.8rem;">INR ${b.total_transferred.toLocaleString('en-IN', {minimumFractionDigits:2, maximumFractionDigits:2})}</div>
                        </td>
                        <td>
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <button class="btn-clear" style="${favStyle} font-size:1.1rem; cursor:pointer;" onclick="toggleFavoriteBeneficiary(${b.id})" title="Favorite"><i class="${favClass}"></i></button>
                                <button class="btn btn-accent btn-sm" onclick="quickTransferToBeneficiary('${escapeHtml(b.beneficiary_username)}')" style="padding: 2px 10px; font-size: 0.8rem;"><i class="fa-solid fa-paper-plane"></i> Send</button>
                                <button class="btn btn-outline btn-sm" onclick="deleteBeneficiary(${b.id})" style="padding: 2px 10px; font-size: 0.8rem; border-color: rgba(239, 68, 68, 0.4); color: #ef4444;"><i class="fa-solid fa-trash-can"></i></button>
                            </div>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
                
                beneficiaryTotalRows = data.total;
                const totalPages = Math.ceil(beneficiaryTotalRows / 5) || 1;
                document.getElementById("beneficiaryPageIndicator").innerText = `Page ${beneficiaryCurrentPage} of ${totalPages}`;
            } else {
                showToast("Beneficiary Error", data.message || "Failed to load beneficiaries.", "error");
            }
        })
        .catch(err => showToast("Network Error", "Could not retrieve beneficiary list.", "error"));
}

function changeBeneficiaryPage(dir) {
    const totalPages = Math.ceil(beneficiaryTotalRows / 5) || 1;
    const newPage = beneficiaryCurrentPage + dir;
    if (newPage >= 1 && newPage <= totalPages) {
        beneficiaryCurrentPage = newPage;
        loadBeneficiaryList();
    }
}

function submitAddBeneficiary() {
    const username = document.getElementById("addBUsername").value.trim();
    const nickname = document.getElementById("addBNickname").value.trim();
    
    if (!username) {
        showToast("Validation Error", "Username is required.", "error");
        return;
    }
    
    fetch('/api/beneficiaries', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, nickname: nickname || username })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            showToast("Added", "Beneficiary successfully saved.", "success");
            closeAddBeneficiaryModal();
            // Refresh list if open
            if (!document.getElementById("beneficiariesModal").classList.contains("hidden")) {
                loadBeneficiaryList();
            }
        } else {
            showToast("Error", data.message || "Failed to add beneficiary.", "error");
        }
    })
    .catch(err => showToast("Network Error", "Failed to add beneficiary.", "error"));
}

function toggleFavoriteBeneficiary(id) {
    fetch(`/api/beneficiaries/${id}/favorite`, { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                loadBeneficiaryList();
            } else {
                showToast("Error", data.message || "Failed to update favorite.", "error");
            }
        })
        .catch(err => showToast("Network Error", "Failed to favorite beneficiary.", "error"));
}

function deleteBeneficiary(id) {
    if (!confirm("Are you sure you want to remove this beneficiary?")) return;
    
    fetch(`/api/beneficiaries/${id}`, { method: 'DELETE' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showToast("Removed", "Beneficiary removed from list.", "success");
                loadBeneficiaryList();
            } else {
                showToast("Error", data.message || "Failed to remove beneficiary.", "error");
            }
        })
        .catch(err => showToast("Network Error", "Failed to remove beneficiary.", "error"));
}

function quickTransferToBeneficiary(username) {
    closeBeneficiariesModal();
    // Fill the normal transfer form and focus
    const dest = document.getElementById("transferDestAccount") || document.getElementById("receiver");
    if (dest) {
        dest.value = username;
        dest.focus();
        showToast("Quick Transfer", `Pre-filled recipient @${username}`, "info");
    } else {
        showToast("Error", "Transfer form not found.", "error");
    }
}

// Simple escape function to prevent XSS
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}


// ==========================================
// PHASE 3 – LOGIN SECURITY CENTER CLIENT WORKFLOWS
// ==========================================

let sessionCurrentPage = 1;
let sessionTotalRows = 0;

function openSecurityCenterModal() {
    sessionCurrentPage = 1;
    loadSessionList();
    document.getElementById("securityCenterModal").classList.remove("hidden");
}

function closeSecurityCenterModal() {
    document.getElementById("securityCenterModal").classList.add("hidden");
}

function loadSessionList() {
    fetch(`/api/security/sessions?page=${sessionCurrentPage}&per_page=5`)
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const tbody = document.getElementById("sessionTableBody");
                tbody.innerHTML = "";
                
                data.sessions.forEach(s => {
                    const trustIcon = s.is_trusted ? 'fa-shield-heart' : 'fa-shield';
                    const trustText = s.is_trusted ? 'Trusted Device' : 'Untrusted Device';
                    const trustBtnClass = s.is_trusted ? 'btn-accent' : 'btn-outline';
                    
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>
                            <div>
                                <i class="fa-solid fa-desktop text-muted" style="margin-right: 8px;"></i>
                                <strong>${escapeHtml(s.browser)} on ${escapeHtml(s.os)}</strong>
                                ${s.is_current ? '<span class="badge badge-success" style="margin-left: 8px; background: #22c55e; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem;">Current</span>' : ''}
                            </div>
                            <div class="text-muted" style="font-size: 0.8rem; margin-top: 4px;">IP: ${escapeHtml(s.ip_address)} | Type: ${escapeHtml(s.device_type)}</div>
                        </td>
                        <td>
                            <div style="font-size: 0.9rem;">
                                Status: <strong style="color: ${s.status === 'ACTIVE' ? '#22c55e' : '#ef4444'};">${escapeHtml(s.status)}</strong>
                            </div>
                            <div class="text-muted" style="font-size: 0.8rem; margin-top: 4px;">Last active: ${escapeHtml(s.last_activity)}</div>
                        </td>
                        <td>
                            <div style="display: flex; gap: 8px;">
                                <button class="btn btn-sm ${trustBtnClass}" onclick="toggleDeviceTrust('${escapeHtml(s.device_id || 'default_fingerprint')}', ${s.is_trusted ? 0 : 1})" style="padding: 2px 8px; font-size: 0.8rem;" title="${trustText}">
                                    <i class="fa-solid ${trustIcon}"></i>
                                </button>
                                ${s.status === 'ACTIVE' && !s.is_current ? `
                                    <button class="btn btn-outline btn-sm" onclick="revokeSession('${escapeHtml(s.session_id)}')" style="padding: 2px 8px; font-size: 0.8rem; border-color: rgba(239, 68, 68, 0.4); color: #ef4444;">
                                        <i class="fa-solid fa-power-off"></i>
                                    </button>
                                ` : ''}
                            </div>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
                
                sessionTotalRows = data.total;
                const totalPages = Math.ceil(sessionTotalRows / 5) || 1;
                document.getElementById("sessionPageIndicator").innerText = `Page ${sessionCurrentPage} of ${totalPages}`;
            } else {
                showToast("Security Center Error", data.message || "Failed to load active sessions.", "error");
            }
        })
        .catch(err => showToast("Network Error", "Could not load session list.", "error"));
}

function changeSessionPage(dir) {
    const totalPages = Math.ceil(sessionTotalRows / 5) || 1;
    const newPage = sessionCurrentPage + dir;
    if (newPage >= 1 && newPage <= totalPages) {
        sessionCurrentPage = newPage;
        loadSessionList();
    }
}

function revokeSession(sid) {
    if (!confirm("Are you sure you want to terminate this session?")) return;
    
    fetch('/api/security/sessions/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sid })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            showToast("Session Revoked", "The selected session has been terminated.", "success");
            loadSessionList();
        } else {
            showToast("Revocation Failed", data.message || "Failed to terminate session.", "error");
        }
    })
    .catch(err => showToast("Network Error", "Failed to contact revocation service.", "error"));
}

function revokeOtherSessions() {
    if (!confirm("This will terminate all of your active sessions on other browsers and devices. Proceed?")) return;
    
    fetch('/api/security/sessions/revoke-others', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showToast("Sessions Terminated", "All other active sessions have been signed out.", "success");
                loadSessionList();
            } else {
                showToast("Action Failed", data.message || "Failed to terminate other sessions.", "error");
            }
        })
        .catch(err => showToast("Network Error", "Could not complete session termination.", "error"));
}

function toggleDeviceTrust(fingerprint, shouldTrust) {
    fetch('/api/security/devices/trust', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_fingerprint: fingerprint, is_trusted: shouldTrust })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            showToast("Device Updated", "Device trust state successfully updated.", "success");
            loadSessionList();
        } else {
            showToast("Update Failed", data.message || "Failed to change device trust level.", "error");
        }
    })
    .catch(err => showToast("Network Error", "Failed to update device trust status.", "error"));
}


// ==========================================
// PHASE 5 – ENTERPRISE ADMIN EXPORTS & PIE CHART
// ==========================================

function downloadAdminReport(format) {
    window.location.href = `/api/admin/reports/${format}`;
}

let fraudChartInstance = null;
function renderFraudPieChart(totalTxs, totalFrauds) {
    const ctx = document.getElementById('fraudDistributionChart');
    if (!ctx) return;
    
    if (fraudChartInstance) {
        fraudChartInstance.destroy();
    }
    
    const normalTxs = Math.max(0, totalTxs - totalFrauds);
    
    fraudChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Legitimate', 'Flagged Fraud'],
            datasets: [{
                data: [normalTxs, totalFrauds],
                backgroundColor: ['#00f5d4', '#ef4444'],
                borderWidth: 1,
                borderColor: 'rgba(255,255,255,0.1)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#cbd5e1', font: { size: 10 } }
                }
            }
        }
    });
}

function loadEnterpriseAdminStats() {
    fetch('/api/admin/analytics/stats')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const s = data.stats;
                document.getElementById('adminStatUsers').innerText = s.total_users;
                document.getElementById('adminStatTxs').innerText = s.total_transactions;
                document.getElementById('adminStatFrauds').innerText = s.total_frauds;
                document.getElementById('adminStatOtpFailures').innerText = s.otp_failures;
                document.getElementById('adminStatLoginFailures').innerText = s.login_failures;
                document.getElementById('adminStatQrCount').innerText = s.qr_count;
                document.getElementById('adminStatSessions').innerText = s.active_sessions;
                
                // Draw fraud distribution chart
                renderFraudPieChart(s.total_transactions, s.total_frauds);
            }
        })
        .catch(err => console.error("Error loading enterprise admin stats:", err));
}


// ==========================================
// PHASE 6 – NOTIFICATION CENTER CLIENT LOGIC
// ==========================================

let notificationsUnreadOnly = false;

function toggleNotificationDropdown() {
    const el = document.getElementById("notificationDropdown");
    el.classList.toggle("hidden");
    if (!el.classList.contains("hidden")) {
        loadNotificationsList();
    }
}

function toggleUnreadFilter() {
    notificationsUnreadOnly = !notificationsUnreadOnly;
    const btn = document.getElementById("unreadFilterBtn");
    if (notificationsUnreadOnly) {
        btn.innerText = "All Notifications";
        btn.classList.add("btn-accent");
    } else {
        btn.innerText = "Unread Only";
        btn.classList.remove("btn-accent");
    }
    loadNotificationsList();
}

function loadNotificationsList() {
    fetch(`/api/notifications?unread_only=${notificationsUnreadOnly}`)
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const badge = document.getElementById("notificationBadge");
                if (data.unread_count > 0) {
                    badge.innerText = data.unread_count;
                    badge.classList.remove("hidden");
                } else {
                    badge.classList.add("hidden");
                }
                
                const container = document.getElementById("notificationsContainer");
                container.innerHTML = "";
                
                if (data.notifications.length === 0) {
                    container.innerHTML = `<div class="text-muted text-center" style="padding: 15px 0;">No notifications found.</div>`;
                    return;
                }
                
                data.notifications.forEach(n => {
                    let icon = 'fa-info-circle';
                    let color = '#cbd5e1';
                    if (n.type === 'TRANSFER') { icon = 'fa-paper-plane'; color = '#00f5d4'; }
                    else if (n.type === 'DEPOSIT') { icon = 'fa-circle-down'; color = '#10b981'; }
                    else if (n.type === 'SECURITY') { icon = 'fa-shield-halved'; color = '#ef4444'; }
                    
                    const item = document.createElement("div");
                    item.style.background = n.is_read ? 'rgba(255,255,255,0.02)' : 'rgba(255,255,255,0.06)';
                    item.style.border = '1px solid rgba(255,255,255,0.06)';
                    item.style.borderRadius = '8px';
                    item.style.padding = '8px 12px';
                    item.style.display = 'flex';
                    item.style.justify = 'space-between';
                    item.style.alignItems = 'flex-start';
                    item.style.gap = '8px';
                    
                    item.innerHTML = `
                        <div style="display: flex; gap: 8px;">
                            <i class="fa-solid ${icon}" style="color: ${color}; margin-top: 3px; font-size: 0.95rem;"></i>
                            <div>
                                <div style="font-weight: bold; color: ${n.is_read ? '#94a3b8' : '#fff'};">${escapeHtml(n.title)}</div>
                                <div style="font-size: 0.72rem; color: #94a3b8; margin-top: 2px;">${escapeHtml(n.message)}</div>
                                <div style="font-size: 0.65rem; color: #64748b; margin-top: 4px;">${escapeHtml(n.created_at)}</div>
                            </div>
                        </div>
                        <div style="display: flex; flex-direction: column; gap: 6px; align-items: flex-end;">
                            ${!n.is_read ? `
                                <button class="btn btn-sm btn-outline" onclick="markSingleNotificationRead(${n.id})" style="padding: 1px 4px; font-size: 0.6rem; border-radius: 3px;" title="Mark Read">
                                    <i class="fa-solid fa-check"></i>
                                </button>
                            ` : ''}
                            <button class="btn btn-sm btn-outline" onclick="deleteNotification(${n.id})" style="padding: 1px 4px; font-size: 0.6rem; border-radius: 3px; color: #ef4444; border-color: rgba(239, 68, 68, 0.2);" title="Delete">
                                <i class="fa-solid fa-trash-can"></i>
                            </button>
                        </div>
                    `;
                    container.appendChild(item);
                });
            }
        })
        .catch(err => console.error("Error loading notifications:", err));
}

function markAllNotificationsRead() {
    fetch('/api/notifications/read', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                loadNotificationsList();
            }
        })
        .catch(err => console.error("Error marking all read:", err));
}

function markSingleNotificationRead(nid) {
    fetch(`/api/notifications/${nid}/read`, { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                loadNotificationsList();
            }
        })
        .catch(err => console.error("Error marking read:", err));
}

function deleteNotification(nid) {
    fetch(`/api/notifications/${nid}`, { method: 'DELETE' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                loadNotificationsList();
            }
        })
        .catch(err => console.error("Error deleting notification:", err));
}

// Auto load notifications count every 30s
setInterval(() => {
    if (typeof currentUser !== 'undefined' && currentUser.username) {
        fetch('/api/notifications?unread_only=true')
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    const badge = document.getElementById("notificationBadge");
                    if (data.unread_count > 0) {
                        badge.innerText = data.unread_count;
                        badge.classList.remove("hidden");
                    } else {
                        badge.classList.add("hidden");
                    }
                }
            }).catch(e => {});
    }
}, 30000);


// ==========================================
// PHASE 7 – CLIENT DASHBOARD SPEND CHARTS & METRICS
// ==========================================

let clientSpendChartInstance = null;
function renderClientSpendChart(txs) {
    const ctx = document.getElementById('clientSpendChart');
    if (!ctx) return;
    
    if (clientSpendChartInstance) {
        clientSpendChartInstance.destroy();
    }
    
    const days = [];
    const spends = {};
    for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        const dateStr = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        days.push(dateStr);
        spends[dateStr] = 0;
    }
    
    txs.forEach(t => {
        if (t.sender === currentUser.username && t.type !== 'ADD_MONEY' && t.status === 'APPROVED') {
            const txDate = new Date(t.timestamp);
            const dateStr = txDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            if (spends[dateStr] !== undefined) {
                spends[dateStr] += t.amount;
            }
        }
    });
    
    const dataValues = days.map(d => spends[d]);
    
    clientSpendChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: days,
            datasets: [{
                label: 'Daily Spends (Rs)',
                data: dataValues,
                backgroundColor: 'rgba(56, 189, 248, 0.4)',
                borderColor: '#38bdf8',
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#94a3b8' } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } }
            }
        }
    });
}

function loadDashboardMetrics() {
    fetch('/api/dashboard/metrics')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const m = data.metrics;
                document.getElementById('clientBalance').innerText = m.bank_balance.toLocaleString('en-IN', { minimumFractionDigits: 2 });
                document.getElementById('walletBalance').innerText = m.wallet_balance.toLocaleString('en-IN', { minimumFractionDigits: 2 });
                document.getElementById('monthlySpendsValue').innerText = m.monthly_spends.toLocaleString('en-IN', { minimumFractionDigits: 2 });
                document.getElementById('dashboardSecurityScore').innerText = m.security_score;
                
                const scoreEl = document.getElementById('dashboardSecurityScore');
                if (m.security_score >= 80) scoreEl.style.color = '#34d399';
                else if (m.security_score >= 50) scoreEl.style.color = '#fbbf24';
                else scoreEl.style.color = '#f87171';
            }
        })
        .catch(err => console.error("Error loading dashboard metrics:", err));
}

// --- Enterprise Features Logic (Features 1, 2, 3, 5, 6, 9) ---

let currentTxs = [];
let cachedAnalytics = null;

function closeLoginMfaModal() {
    document.getElementById('loginMfaModal').classList.add('hidden');
    document.getElementById('loginMfaCode').value = '';
}

function submitLoginMfa() {
    const otp = document.getElementById('loginMfaCode').value.trim();
    if (!otp) {
        showToast('Verification Error', 'Please enter the verification code.', 'error');
        return;
    }
    
    const btn = document.querySelector('#loginMfaModal .btn-accent');
    const originalHTML = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...';
    
    fetch('/api/login/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp })
    })
    .then(async res => {
        const data = await res.json();
        btn.disabled = false;
        btn.innerHTML = originalHTML;
        
        if (res.status === 200 && data.status === 'success') {
            currentUser = data.user;
            closeLoginMfaModal();
            showToast('Login Success', 'Successfully logged in!', 'success');
            showMainLayout();
        } else {
            showToast('Verification Error', data.message || 'Invalid code.', 'error');
        }
    })
    .catch(() => {
        btn.disabled = false;
        btn.innerHTML = originalHTML;
        showToast('Network Error', 'Could not establish connection.', 'error');
    });
}

function openStatementModal() {
    document.getElementById('statementModal').classList.remove('hidden');
    // Set default dates
    const end = new Date().toISOString().split('T')[0];
    const start = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    document.getElementById('statementStart').value = start;
    document.getElementById('statementEnd').value = end;
}

function closeStatementModal() {
    document.getElementById('statementModal').classList.add('hidden');
}

function downloadStatementPDF() {
    const start = document.getElementById('statementStart').value;
    const end = document.getElementById('statementEnd').value;
    if (!start || !end) {
        showToast('Filter Error', 'Please select both start and end dates.', 'error');
        return;
    }
    window.open(`/api/statement/download?start_date=${start}&end_date=${end}`, '_blank');
    closeStatementModal();
}

function downloadReceiptPDF(txId) {
    window.open(`/api/transaction/${txId}/receipt/pdf`, '_blank');
}

function loadFinancialInsights() {
    fetch('/api/analytics/insights')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const ins = data.insights;
                document.getElementById('insightSpending').innerText = 'Rs ' + ins.monthly_spending.toLocaleString('en-IN', { minimumFractionDigits: 2 });
                document.getElementById('insightIncome').innerText = 'Rs ' + ins.monthly_income.toLocaleString('en-IN', { minimumFractionDigits: 2 });
                document.getElementById('insightSavings').innerText = 'Rs ' + ins.savings.toLocaleString('en-IN', { minimumFractionDigits: 2 });
                document.getElementById('insightLargest').innerText = 'Rs ' + ins.largest_expense.toLocaleString('en-IN', { minimumFractionDigits: 2 });
                document.getElementById('insightComparison').innerText = ins.comparison_message;
            }
        });
}

function switchAnalyticsChart() {
    const type = document.getElementById('analyticsChartSelect').value;
    const ctx = document.getElementById('clientSpendChart');
    if (!ctx || !cachedAnalytics) return;
    
    if (clientSpendChartInstance) {
        clientSpendChartInstance.destroy();
    }
    
    let labels = [];
    let data = [];
    let labelName = "";
    let bgColor = "";
    let borderColor = "";
    
    if (type === 'spend') {
        renderClientSpendChart(currentTxs);
        document.getElementById('chartDesc').innerHTML = `Total Spends in the last 30 days: Rs <span id="monthlySpendsValue">${cachedAnalytics.monthly_withdrawals.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</span>`;
        return;
    }
    
    if (type === 'deposits') {
        labels = ['Last 30 Days'];
        data = [cachedAnalytics.monthly_deposits];
        labelName = 'Monthly Deposits (Rs)';
        bgColor = 'rgba(16, 185, 129, 0.4)';
        borderColor = '#10b981';
        document.getElementById('chartDesc').innerHTML = `Deposits credited in last 30 days: Rs <span>${cachedAnalytics.monthly_deposits.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</span>`;
    } else if (type === 'withdrawals') {
        labels = ['Last 30 Days'];
        data = [cachedAnalytics.monthly_withdrawals];
        labelName = 'Monthly Withdrawals (Rs)';
        bgColor = 'rgba(244, 63, 94, 0.4)';
        borderColor = '#f43f5e';
        document.getElementById('chartDesc').innerHTML = `Withdrawals debited in last 30 days: Rs <span>${cachedAnalytics.monthly_withdrawals.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</span>`;
    } else if (type === 'transfers') {
        labels = ['Last 30 Days'];
        data = [cachedAnalytics.monthly_transfers];
        labelName = 'Monthly Transfers (Rs)';
        bgColor = 'rgba(155, 93, 229, 0.4)';
        borderColor = '#9b5de5';
        document.getElementById('chartDesc').innerHTML = `Transfers sent in last 30 days: Rs <span>${cachedAnalytics.monthly_transfers.toLocaleString('en-IN', { minimumFractionDigits: 2 })}</span>`;
    } else if (type === 'fraud') {
        labels = ['Blocked Attempts', 'High Risk Tx'];
        data = [cachedAnalytics.fraud_attempts, cachedAnalytics.high_risk_transactions];
        labelName = 'Risk Events (Count)';
        bgColor = 'rgba(239, 68, 68, 0.4)';
        borderColor = '#ef4444';
        document.getElementById('chartDesc').innerHTML = `Risk management blockages and warnings in last 30 days`;
    } else if (type === 'trend') {
        const trend = cachedAnalytics.balance_trend || [];
        labels = trend.map(t => new Date(t.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
        data = trend.map(t => t.balance);
        labelName = 'Account Balance History (Rs)';
        bgColor = 'rgba(6, 182, 212, 0.2)';
        borderColor = '#06b6d4';
        document.getElementById('chartDesc').innerHTML = `Chronological balance movements for verified transactions`;
    }
    
    clientSpendChartInstance = new Chart(ctx, {
        type: type === 'trend' ? 'line' : 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: labelName,
                data: data,
                backgroundColor: bgColor,
                borderColor: borderColor,
                borderWidth: 1.5,
                borderRadius: 4,
                fill: type === 'trend'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: true }
            }
        }
    });
}

let currentSecurityTab = 'sessions';
function switchSecurityTab(tab) {
    currentSecurityTab = tab;
    
    document.getElementById('secTabSessionsBtn').classList.toggle('active', tab === 'sessions');
    document.getElementById('secTabDevicesBtn').classList.toggle('active', tab === 'devices');
    document.getElementById('secTabHistoryBtn').classList.toggle('active', tab === 'history');
    
    document.getElementById('secPaneSessions').classList.toggle('hidden', tab !== 'sessions');
    document.getElementById('secPaneDevices').classList.toggle('hidden', tab !== 'devices');
    document.getElementById('secPaneHistory').classList.toggle('hidden', tab !== 'history');
    
    if (tab === 'sessions') {
        loadSessions();
    } else if (tab === 'devices') {
        loadTrustedDevices();
    } else if (tab === 'history') {
        loadLoginHistory();
    }
}

function loadTrustedDevices() {
    fetch('/api/security/devices')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const tbody = document.getElementById('trustedDevicesTableBody');
                tbody.innerHTML = '';
                if (data.devices.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No trusted devices found.</td></tr>';
                    return;
                }
                data.devices.forEach(d => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${escapeHtml(d.browser)}</td>
                        <td>${escapeHtml(d.os)}</td>
                        <td>${formatDate(d.last_login_at)}</td>
                        <td>
                            <button class="btn btn-danger btn-sm" onclick="revokeDevice(${d.id})" style="padding: 2px 6px; font-size: 0.75rem; border-radius: 4px;">Revoke</button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            }
        });
}

function revokeDevice(id) {
    if (!confirm('Are you sure you want to revoke trust for this device? You will need to enter an OTP code on your next login.')) return;
    fetch(`/api/security/devices/${id}`, { method: 'DELETE' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showToast('Device Revoked', data.message, 'success');
                loadTrustedDevices();
            } else {
                showToast('Error', data.message, 'error');
            }
        });
}

function loadLoginHistory() {
    fetch('/api/security/login-history')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                const tbody = document.getElementById('loginHistoryTableBody');
                tbody.innerHTML = '';
                if (data.history.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No login logs recorded.</td></tr>';
                    return;
                }
                data.history.forEach(h => {
                    const row = document.createElement('tr');
                    const badgeClass = h.status === 'ACTIVE' || h.status === 'SUCCESS' ? 'badge-success' : 'badge-danger';
                    row.innerHTML = `
                        <td>${formatDate(h.timestamp)}</td>
                        <td>${escapeHtml(h.ip_address)}</td>
                        <td>${escapeHtml(h.browser)} (${escapeHtml(h.os)})</td>
                        <td><span class="badge ${badgeClass}">${escapeHtml(h.status)}</span></td>
                        <td>${escapeHtml(h.country)}</td>
                    `;
                    tbody.appendChild(row);
                });
            }
        });
}

function handlePasswordUpdate(e) {
    e.preventDefault();
    const current_password = document.getElementById('pwdCurrent').value;
    const new_password = document.getElementById('pwdNew').value;
    const confirm_password = document.getElementById('pwdConfirm').value;
    
    if (new_password !== confirm_password) {
        showToast('Password Error', 'New passwords do not match.', 'error');
        return;
    }
    
    fetch('/api/profile/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password, new_password, confirm_password })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            showToast('Password Updated', data.message, 'success');
            document.getElementById('pwdCurrent').value = '';
            document.getElementById('pwdNew').value = '';
            document.getElementById('pwdConfirm').value = '';
        } else {
            showToast('Password Update Error', data.message || 'Failed to update password.', 'error');
        }
    })
    .catch(() => showToast('Network Error', 'Could not establish connection.', 'error'));
}


// --- Razorpay Payment Gateway (Test Mode) Integration ---

function initiateRazorpayPayment(amount) {
    fetch('/api/payment/create-order', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount: amount })
    })
    .then(async res => {
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            const options = {
                key: data.key_id,
                amount: data.amount,
                currency: data.currency || "INR",
                name: "Smart Banking",
                description: "Smart Wallet Top-Up (Test Mode)",
                order_id: data.order_id,
                prefill: {
                    name: data.customer_name || "",
                    email: data.customer_email || "",
                    contact: data.customer_phone || ""
                },
                theme: {
                    color: "#9b5ded"
                },
                handler: function (response) {
                    verifyRazorpayPayment(response, data.reference_id, data.amount_inr);
                },
                modal: {
                    ondismiss: function() {
                        isSubmittingDeposit = false;
                        showToast('Payment Cancelled', 'Razorpay Checkout was cancelled.', 'info');
                    }
                }
            };
            try {
                const rzp = new Razorpay(options);
                rzp.open();
            } catch (err) {
                isSubmittingDeposit = false;
                console.error("Razorpay Checkout Launch Error:", err);
                showToast('Payment Error', 'Failed to launch Razorpay Checkout.', 'error');
            }
        } else {
            isSubmittingDeposit = false;
            showToast('Order Error', data.message || 'Could not create Razorpay payment order.', 'error');
        }
    })
    .catch(err => {
        isSubmittingDeposit = false;
        console.error("Create Order Error:", err);
        showToast('Network Error', 'Connection to payment server failed.', 'error');
    });
}

function verifyRazorpayPayment(response, referenceId, amountInr) {
    showToast('Verifying Payment', 'Cryptographically verifying Razorpay payment signature...', 'info');
    fetch('/api/payment/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            razorpay_order_id: response.razorpay_order_id,
            razorpay_payment_id: response.razorpay_payment_id,
            razorpay_signature: response.razorpay_signature,
            reference_id: referenceId
        })
    })
    .then(async res => {
        isSubmittingDeposit = false;
        const data = await res.json();
        if (res.status === 200 && data.status === 'success') {
            closeAddMoneyModal();
            loadDashboardData();
            showToast('Payment Successful', `INR ${data.amount || amountInr} added to your Smart Wallet!`, 'success');
        } else {
            showToast('Verification Failed', data.message || 'Signature verification failed. Wallet balance was NOT changed.', 'error');
        }
    })
    .catch(err => {
        isSubmittingDeposit = false;
        console.error("Payment Verification Error:", err);
        showToast('Network Error', 'Verification connection failed.', 'error');
    });
}
