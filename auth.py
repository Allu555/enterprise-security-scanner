# ============================================================================
# auth.py - Complete Authentication & Authorization System
# ============================================================================
import streamlit as st
from typing import Optional, Dict, Tuple, Callable
from datetime import datetime
import re
from functools import wraps
from database import (
    SessionDB, 
    UserDB, 
    ActivityLog, 
    SystemSettingsDB,
    get_db_connection
)

# ============================================================================
# INITIALIZATION
# ============================================================================

def init_auth():
    """Initialize authentication system - called at app startup"""
    if 'session_token' not in st.session_state:
        st.session_state['session_token'] = None
    
    if 'auth_initialized' not in st.session_state:
        st.session_state['auth_initialized'] = True
        
        # Clean up expired sessions on startup
        try:
            SessionDB.clean_expired_sessions()
        except Exception as e:
            print(f"Error cleaning sessions: {e}")


def auth_guard(required_role: str = None):
    """
    Authentication guard decorator for protecting routes.
    Usage: @auth_guard() or @auth_guard('admin')
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not is_authenticated():
                st.warning("🔒 Please login to access this page")
                st.session_state['redirect_to_login'] = True
                st.stop()
            
            user = get_current_user()
            
            if required_role and user.get('role') != required_role:
                st.error(f"⛔ Access denied. {required_role.title()} privileges required.")
                st.stop()
            
            if not user.get('is_active', True):
                st.error("⛔ Your account has been deactivated. Please contact administrator.")
                logout()
                st.stop()
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

def get_current_user() -> Optional[Dict]:
    """
    Get current authenticated user from session.
    Returns user dict if valid session exists, None otherwise.
    """
    if 'session_token' in st.session_state and st.session_state['session_token']:
        session = SessionDB.validate_session(st.session_state['session_token'])
        if session:
            return {
                'id': session['user_id'],
                'username': session['username'],
                'role': session['role'],
                'email': session['email'],
                'is_active': session['is_active'],
                'full_name': session.get('full_name', '')
            }
    return None


def is_authenticated() -> bool:
    """Check if user is authenticated"""
    return get_current_user() is not None


def is_admin() -> bool:
    """Check if current user is admin"""
    user = get_current_user()
    return user is not None and user.get('role') == 'admin'


def logout():
    """Logout current user - invalidate session and clear session state"""
    if 'session_token' in st.session_state and st.session_state['session_token']:
        # Log the logout action
        user = get_current_user()
        if user:
            try:
                ActivityLog.log(
                    user_id=user['id'],
                    username=user['username'],
                    action="logout",
                    status="success",
                    details={"method": "manual_logout"}
                )
            except:
                pass
        
        # Invalidate session in database
        try:
            SessionDB.invalidate_session(st.session_state['session_token'])
        except:
            pass
        
        # Clear session state
        st.session_state['session_token'] = None
    
    # Clear all session state except specific keys
    keys_to_keep = ['theme', 'language', 'auth_initialized']
    for key in list(st.session_state.keys()):
        if key not in keys_to_keep:
            del st.session_state[key]
    
    st.rerun()


# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

def login_user(username: str, password: str) -> Tuple[bool, str, Optional[Dict]]:
    """
    Authenticate and login user.
    Returns (success, message, user_data)
    """
    if not username or not password:
        return False, "Please enter both username and password", None
    
    try:
        # Attempt authentication
        user = UserDB.authenticate_user(username, password)
        
        if user:
            # Create session
            session_token = SessionDB.create_session(
                user_id=user['id'],
                ip_address=_get_client_ip(),
                user_agent=_get_user_agent()
            )
            
            # Store in session state
            st.session_state['session_token'] = session_token
            
            # Log successful login
            ActivityLog.log(
                user_id=user['id'],
                username=user['username'],
                action="login",
                status="success",
                ip_address=_get_client_ip(),
                user_agent=_get_user_agent(),
                details={"method": "password"}
            )
            
            return True, f"Welcome back, {user['username']}!", user
        else:
            # Log failed login attempt
            ActivityLog.log(
                user_id=None,
                username=username,
                action="login",
                status="failed",
                ip_address=_get_client_ip(),
                user_agent=_get_user_agent(),
                details={"reason": "invalid_credentials"}
            )
            
            return False, "Invalid username/email or password", None
            
    except ValueError as e:
        # Account locked error
        ActivityLog.log(
            user_id=None,
            username=username,
            action="login",
            status="failed",
            ip_address=_get_client_ip(),
            user_agent=_get_user_agent(),
            details={"reason": "account_locked", "message": str(e)}
        )
        
        return False, str(e), None
    except Exception as e:
        return False, f"Login failed: {str(e)}", None


def register_user(username: str, email: str, password: str, full_name: str = None) -> Tuple[bool, str, Optional[Dict]]:
    """
    Register a new user.
    Returns (success, message, user_data)
    """
    # Validation
    if not username or not email or not password:
        return False, "Username, email, and password are required", None
    
    if not validate_email(email):
        return False, "Please enter a valid email address", None
    
    is_strong, strength_msg = validate_password_strength(password)
    if not is_strong:
        return False, strength_msg, None
    
    try:
        # Create user
        user = UserDB.create_user(
            username=username,
            email=email,
            password=password,
            full_name=full_name,
            role='user'
        )
        
        # Log registration
        ActivityLog.log(
            user_id=user['id'],
            username=user['username'],
            action="register",
            status="success",
            ip_address=_get_client_ip(),
            user_agent=_get_user_agent()
        )
        
        return True, "Account created successfully! Please login.", user
        
    except ValueError as e:
        return False, str(e), None
    except Exception as e:
        return False, f"Registration failed: {str(e)}", None


def change_user_password(user_id: int, old_password: str, new_password: str) -> Tuple[bool, str]:
    """
    Change user password.
    Returns (success, message)
    """
    if not old_password or not new_password:
        return False, "Please fill in all fields"
    
    is_strong, strength_msg = validate_password_strength(new_password)
    if not is_strong:
        return False, strength_msg
    
    try:
        success = UserDB.change_password(user_id, old_password, new_password)
        
        if success:
            # Log password change
            user = get_current_user()
            if user:
                ActivityLog.log(
                    user_id=user['id'],
                    username=user['username'],
                    action="password_change",
                    status="success",
                    details={"method": "self_change"}
                )
            
            return True, "Password updated successfully!"
        else:
            return False, "Current password is incorrect"
            
    except Exception as e:
        return False, f"Failed to update password: {str(e)}"


def reset_user_password(user_id: int, new_password: str, admin_id: int = None) -> Tuple[bool, str]:
    """
    Admin force reset user password.
    Returns (success, message)
    """
    if len(new_password) < 6:
        return False, "Password must be at least 6 characters"
    
    try:
        success = UserDB.admin_reset_password(user_id, new_password)
        
        if success:
            # Log password reset
            admin = get_current_user() if not admin_id else UserDB.get_user_by_id(admin_id)
            target_user = UserDB.get_user_by_id(user_id)
            
            if admin and target_user:
                ActivityLog.log(
                    user_id=admin['id'],
                    username=admin['username'],
                    action="password_reset",
                    resource_type="user",
                    resource_id=str(user_id),
                    details={"target_user": target_user['username']},
                    status="success"
                )
            
            return True, "Password reset successfully!"
        else:
            return False, "Failed to reset password"
            
    except Exception as e:
        return False, f"Failed to reset password: {str(e)}"


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Strong password"


# ============================================================================
# STYLING FUNCTIONS
# ============================================================================

def apply_auth_styling():
    """Apply professional styling for auth pages"""
    st.markdown("""
        <style>
        /* Main Auth Container */
        .auth-container {
            max-width: 480px;
            margin: 0 auto;
            padding: 2.5rem;
            background: rgba(15, 12, 41, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            border: 1px solid rgba(66, 135, 245, 0.3);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        
        /* Auth Header */
        .auth-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .auth-header h1 {
            background: linear-gradient(135deg, #4287f5, #673AB7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .auth-header p {
            color: #a0a0a0;
            font-size: 1rem;
        }
        
        /* Form Elements */
        .auth-form {
            margin-top: 1.5rem;
        }
        
        .stTextInput > div > div > input {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(66, 135, 245, 0.3);
            border-radius: 10px;
            color: white;
            padding: 0.75rem 1rem;
            font-size: 1rem;
            transition: all 0.3s;
        }
        
        .stTextInput > div > div > input:focus {
            border-color: #4287f5;
            box-shadow: 0 0 0 3px rgba(66, 135, 245, 0.2);
        }
        
        .stTextInput > div > div > input::placeholder {
            color: rgba(255, 255, 255, 0.5);
        }
        
        /* Buttons */
        .stButton > button {
            background: linear-gradient(135deg, #4287f5, #673AB7);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 0.75rem 1.5rem;
            font-weight: 600;
            transition: all 0.3s;
            width: 100%;
            margin-top: 0.5rem;
        }
        
        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(66, 135, 245, 0.4);
        }
        
        .stButton > button:active {
            transform: translateY(0);
        }
        
        /* Secondary Button */
        .secondary-btn > button {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(66, 135, 245, 0.3);
            color: white;
        }
        
        .secondary-btn > button:hover {
            background: rgba(66, 135, 245, 0.2);
            border-color: #4287f5;
        }
        
        /* Password Strength Indicator */
        .password-strength {
            margin-top: 0.5rem;
            padding: 0.75rem;
            border-radius: 8px;
            font-size: 0.9rem;
        }
        
        .strength-weak {
            background: rgba(220, 53, 69, 0.2);
            border-left: 4px solid #dc3545;
            color: #dc3545;
        }
        
        .strength-medium {
            background: rgba(255, 193, 7, 0.2);
            border-left: 4px solid #ffc107;
            color: #ffc107;
        }
        
        .strength-strong {
            background: rgba(40, 167, 69, 0.2);
            border-left: 4px solid #28a745;
            color: #28a745;
        }
        
        /* Divider */
        .auth-divider {
            display: flex;
            align-items: center;
            text-align: center;
            margin: 1.5rem 0;
            color: rgba(255, 255, 255, 0.5);
        }
        
        .auth-divider::before,
        .auth-divider::after {
            content: '';
            flex: 1;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .auth-divider span {
            padding: 0 1rem;
        }
        
        /* Links */
        .auth-link {
            color: #4287f5;
            text-decoration: none;
            transition: color 0.3s;
            cursor: pointer;
        }
        
        .auth-link:hover {
            color: #673AB7;
            text-decoration: underline;
        }
        
        /* Success/Error Messages */
        .stAlert {
            background: rgba(15, 12, 41, 0.95);
            border: 1px solid rgba(66, 135, 245, 0.3);
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        /* Loading Spinner */
        .stSpinner > div {
            border-color: #4287f5 transparent #4287f5 transparent;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .auth-container {
                margin: 1rem;
                padding: 1.5rem;
            }
        }
        
        /* Animated Background */
        .auth-background {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            z-index: -1;
        }
        
        .auth-background::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg width="60" height="60" xmlns="http://www.w3.org/2000/svg"><rect width="60" height="60" fill="none"/><circle cx="30" cy="30" r="2" fill="rgba(66, 135, 245, 0.1)"/></svg>');
            opacity: 0.1;
            animation: pulse 4s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 0.1; }
            50% { opacity: 0.15; }
        }
        
        /* Feature Cards */
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-top: 2rem;
        }
        
        .feature-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid rgba(66, 135, 245, 0.2);
            transition: all 0.3s;
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
            border-color: #4287f5;
            background: rgba(66, 135, 245, 0.1);
        }
        
        .feature-icon {
            font-size: 2rem;
            margin-bottom: 1rem;
        }
        
        .feature-title {
            color: white;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .feature-description {
            color: #a0a0a0;
            font-size: 0.9rem;
        }
        
        /* Terms and Privacy */
        .terms-text {
            color: rgba(255, 255, 255, 0.7);
            font-size: 0.8rem;
            text-align: center;
            margin-top: 1.5rem;
        }
        
        .terms-text a {
            color: #4287f5;
            text-decoration: none;
        }
        
        .terms-text a:hover {
            text-decoration: underline;
        }
        
        /* Input Icons */
        .input-icon {
            position: relative;
        }
        
        .input-icon i {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: rgba(255, 255, 255, 0.5);
        }
        
        /* Checkbox */
        .stCheckbox > div > label {
            color: rgba(255, 255, 255, 0.9);
        }
        
        .stCheckbox > div > label > span {
            border-color: rgba(66, 135, 245, 0.5);
        }
        
        /* Tooltips */
        .tooltip-icon {
            color: #4287f5;
            cursor: help;
            margin-left: 0.5rem;
        }
        </style>
    """, unsafe_allow_html=True)


def render_auth_background():
    """Render animated background for auth pages"""
    st.markdown('<div class="auth-background"></div>', unsafe_allow_html=True)


def render_feature_cards():
    """Render feature cards for auth page"""
    st.markdown("""
        <div class="feature-grid">
            <div class="feature-card">
                <div class="feature-icon">🛡️</div>
                <div class="feature-title">AI-Powered Scanning</div>
                <div class="feature-description">Advanced vulnerability detection with machine learning</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔍</div>
                <div class="feature-title">Comprehensive Tests</div>
                <div class="feature-description">SQLi, XSS, Command Injection & more</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">📊</div>
                <div class="feature-title">Real-Time Analytics</div>
                <div class="feature-description">Live monitoring and detailed reports</div>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔐</div>
                <div class="feature-title">Enterprise Security</div>
                <div class="feature-description">SSL/TLS, headers & advanced recon</div>
            </div>
        </div>
    """, unsafe_allow_html=True)


def render_password_strength_indicator(password: str):
    """Render a visual password strength indicator"""
    if not password:
        return
    
    is_strong, message = validate_password_strength(password)
    
    # Calculate strength score
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r'[A-Z]', password): score += 1
    if re.search(r'[a-z]', password): score += 1
    if re.search(r'[0-9]', password): score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 1
    
    strength_class = "strength-weak"
    strength_text = "Weak Password"
    if score >= 4:
        strength_class = "strength-strong"
        strength_text = "Strong Password"
    elif score >= 3:
        strength_class = "strength-medium"
        strength_text = "Medium Password"
    
    # Progress bar
    percentage = (score / 5) * 100
    
    st.markdown(f"""
        <div class="password-strength {strength_class}">
            <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                <span>{strength_text}</span>
                <span>{score}/5</span>
            </div>
            <div style="height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px;">
                <div style="width: {percentage}%; height: 100%; background: {'#28a745' if score >=4 else '#ffc107' if score >=3 else '#dc3545'}; border-radius: 2px;"></div>
            </div>
            <div style="margin-top: 8px; font-size: 0.85rem;">
                {message}
            </div>
        </div>
    """, unsafe_allow_html=True)


# ============================================================================
# UI RENDERING FUNCTIONS
# ============================================================================

def render_login_page():
    """Render the login page with enhanced UI"""
    apply_auth_styling()
    render_auth_background()
    
    # Center container
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown('<div class="auth-container">', unsafe_allow_html=True)
        
        # Header
        st.markdown("""
            <div class="auth-header">
                <h1>🛡️ Security Scanner</h1>
                <p>Welcome back! Please login to continue</p>
            </div>
        """, unsafe_allow_html=True)
        
        # Check if system is in maintenance mode
        if SystemSettingsDB.is_maintenance_mode():
            st.warning("⚠️ System is currently under maintenance. Please try again later.")
            return None
        
        # Login form
        with st.form("login_form", clear_on_submit=False):
            # Username/Email field
            username = st.text_input(
                "Username or Email", 
                placeholder="Enter your username or email",
                key="login_username"
            )
            
            # Password field
            password = st.text_input(
                "Password", 
                type="password", 
                placeholder="Enter your password",
                key="login_password"
            )
            
            # Remember me checkbox
            col_a, col_b = st.columns(2)
            with col_a:
                remember_me = st.checkbox("Remember me")
            with col_b:
                st.markdown("""
                    <div style="text-align: right; margin-top: 8px;">
                        <span class="auth-link" onclick="document.getElementById('forgot-password').click()">Forgot Password?</span>
                    </div>
                """, unsafe_allow_html=True)
            
            # Login button
            submit = st.form_submit_button("🔑 Login", use_container_width=True, type="primary")
            
            if submit:
                with st.spinner("Authenticating..."):
                    success, message, user = login_user(username, password)
                    if success:
                        st.success(f"✅ {message}")
                        st.session_state['page'] = 'dashboard'
                        st.rerun()
                        return user
                    else:
                        st.error(f"❌ {message}")
        
        # Divider
        st.markdown("""
            <div class="auth-divider">
                <span>OR</span>
            </div>
        """, unsafe_allow_html=True)
        
        # Registration section
        if SystemSettingsDB.is_registration_enabled():
            st.markdown("""
                <div style="text-align: center; margin-bottom: 1rem;">
                    <p style="color: rgba(255,255,255,0.7);">New to Security Scanner?</p>
                </div>
            """, unsafe_allow_html=True)
            
            col_a, col_b, col_c = st.columns([1, 2, 1])
            with col_b:
                if st.button("📝 Create New Account", use_container_width=True, key="register_btn"):
                    st.session_state['page'] = 'register'
                    st.rerun()
        
        # Forgot password hidden button
        if st.button("", key="forgot-password", help="Forgot Password"):
            st.session_state['page'] = 'forgot_password'
            st.rerun()
        
        # Terms and privacy
        st.markdown("""
            <div class="terms-text">
                By logging in, you agree to our 
                <a href="#">Terms of Service</a> and 
                <a href="#">Privacy Policy</a>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Feature cards
        st.markdown("---")
        render_feature_cards()
    
    return None


def render_register_page():
    """Render the registration page with enhanced UI"""
    apply_auth_styling()
    render_auth_background()
    
    # Check if registration is enabled
    if not SystemSettingsDB.is_registration_enabled():
        st.warning("⚠️ Registration is currently disabled. Please contact administrator.")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("← Back to Login", use_container_width=True):
                st.session_state['page'] = 'login'
                st.rerun()
        return None
    
    # Center container
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown('<div class="auth-container">', unsafe_allow_html=True)
        
        # Header
        st.markdown("""
            <div class="auth-header">
                <h1>📝 Create Account</h1>
                <p>Join our security scanning platform</p>
            </div>
        """, unsafe_allow_html=True)
        
        # Registration form
        with st.form("register_form", clear_on_submit=False):
            col_a, col_b = st.columns(2)
            
            with col_a:
                username = st.text_input(
                    "Username*", 
                    placeholder="Choose a username",
                    key="reg_username"
                )
                email = st.text_input(
                    "Email*", 
                    placeholder="your@email.com",
                    key="reg_email"
                )
            
            with col_b:
                full_name = st.text_input(
                    "Full Name", 
                    placeholder="Your full name",
                    key="reg_fullname"
                )
                password = st.text_input(
                    "Password*", 
                    type="password", 
                    placeholder="Create password",
                    key="reg_password"
                )
            
            confirm_password = st.text_input(
                "Confirm Password*", 
                type="password", 
                placeholder="Confirm password",
                key="reg_confirm"
            )
            
            # Password strength indicator
            if password:
                render_password_strength_indicator(password)
            
            # Terms agreement
            agree_terms = st.checkbox(
                "I agree to the Terms of Service and Privacy Policy*",
                value=False
            )
            
            st.markdown("---")
            
            col_a, col_b = st.columns(2)
            
            with col_a:
                submit = st.form_submit_button(
                    "✅ Create Account", 
                    use_container_width=True, 
                    type="primary"
                )
            
            with col_b:
                if st.form_submit_button("← Back to Login", use_container_width=True):
                    st.session_state['page'] = 'login'
                    st.rerun()
            
            if submit:
                # Validation
                if not agree_terms:
                    st.error("❌ You must agree to the Terms of Service and Privacy Policy")
                    return None
                
                if password != confirm_password:
                    st.error("❌ Passwords do not match")
                    return None
                
                with st.spinner("Creating your account..."):
                    success, message, user = register_user(username, email, password, full_name)
                    if success:
                        st.success(f"✅ {message}")
                        st.balloons()
                        st.session_state['page'] = 'login'
                        st.rerun()
                        return user
                    else:
                        st.error(f"❌ {message}")
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    return None


def render_forgot_password_page():
    """Render forgot password page with enhanced UI"""
    apply_auth_styling()
    render_auth_background()
    
    # Center container
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown('<div class="auth-container">', unsafe_allow_html=True)
        
        # Header
        st.markdown("""
            <div class="auth-header">
                <h1>🔑 Reset Password</h1>
                <p>Enter your email to receive reset instructions</p>
            </div>
        """, unsafe_allow_html=True)
        
        with st.form("forgot_password_form"):
            email = st.text_input(
                "Email Address", 
                placeholder="Enter your registered email",
                key="forgot_email"
            )
            
            st.markdown("""
                <div style="background: rgba(66, 135, 245, 0.1); border-radius: 8px; padding: 1rem; margin: 1rem 0;">
                    <p style="color: #4fc3f7; margin: 0; font-size: 0.9rem;">
                        📧 We'll send password reset instructions to this email address.
                    </p>
                </div>
            """, unsafe_allow_html=True)
            
            col_a, col_b = st.columns(2)
            
            with col_a:
                submitted = st.form_submit_button(
                    "📧 Send Reset Link", 
                    type="primary", 
                    use_container_width=True
                )
            
            with col_b:
                if st.form_submit_button("← Back to Login", use_container_width=True):
                    st.session_state['page'] = 'login'
                    st.rerun()
            
            if submitted:
                if not email:
                    st.error("❌ Please enter your email address")
                    return None
                
                if not validate_email(email):
                    st.error("❌ Please enter a valid email address")
                    return None
                
                with st.spinner("Processing request..."):
                    # Check if user exists
                    user = UserDB.get_user_by_email(email)
                    
                    if user:
                        # Log password reset request
                        ActivityLog.log(
                            user_id=user['id'],
                            username=user['username'],
                            action="password_reset_request",
                            status="success",
                            details={"email": email}
                        )
                        
                        st.success("✅ Password reset link has been sent to your email!")
                        st.info("📧 Please check your inbox and spam folder")
                        
                        # Show demo message (in production, this would be a real email)
                        st.markdown("""
                            <div style="background: rgba(40, 167, 69, 0.2); border-radius: 8px; padding: 1rem; margin-top: 1rem;">
                                <p style="color: #28a745; margin: 0;">
                                    <strong>Demo Mode:</strong> Reset link: 
                                    <span style="background: rgba(255,255,255,0.1); padding: 0.25rem 0.5rem; border-radius: 4px; font-family: monospace;">
                                        security-scanner.com/reset?token=demo123
                                    </span>
                                </p>
                            </div>
                        """, unsafe_allow_html=True)
                    else:
                        # Don't reveal that email doesn't exist
                        st.success("✅ If the email exists, a reset link has been sent!")
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    return None


def render_user_profile():
    """Render user profile page with enhanced UI"""
    user = get_current_user()
    if not user:
        st.error("You must be logged in to view profile")
        return
    
    # Profile header
    st.markdown("""
        <div style="text-align: center; margin-bottom: 2rem;">
            <div style="font-size: 4rem; margin-bottom: 1rem;">👤</div>
            <h1 style="background: linear-gradient(135deg, #4287f5, #673AB7); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                User Profile
            </h1>
            <p style="color: #a0a0a0;">Manage your account settings and security</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Profile content
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
            <div style="background: rgba(15, 12, 41, 0.95); backdrop-filter: blur(10px); border-radius: 15px; border: 1px solid rgba(66, 135, 245, 0.3); padding: 1.5rem;">
                <h3 style="color: #4287f5; margin-bottom: 1rem;">📋 Account Information</h3>
            </div>
        """, unsafe_allow_html=True)
        
        # Account details
        info_data = {
            "Username": user['username'],
            "Email": user['email'],
            "Full Name": user.get('full_name', 'Not set'),
            "Role": user['role'].title(),
            "Member Since": user.get('created_at', 'N/A') if hasattr(user, 'get') else 'N/A'
        }
        
        for key, value in info_data.items():
            st.markdown(f"""
                <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid rgba(255,255,255,0.1);">
                    <span style="color: #a0a0a0;">{key}:</span>
                    <span style="color: white; font-weight: 600;">{value}</span>
                </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
            <div style="background: rgba(15, 12, 41, 0.95); backdrop-filter: blur(10px); border-radius: 15px; border: 1px solid rgba(66, 135, 245, 0.3); padding: 1.5rem;">
                <h3 style="color: #4287f5; margin-bottom: 1rem;">🔐 Security Status</h3>
            </div>
        """, unsafe_allow_html=True)
        
        # Get user stats
        from database import ScanHistoryDB
        scan_stats = ScanHistoryDB.get_user_scan_stats(user['id'])
        
        # Status indicators
        st.markdown(f"""
            <div style="display: flex; align-items: center; margin-bottom: 1rem;">
                <div style="width: 12px; height: 12px; background: {'#28a745' if user.get('is_active') else '#dc3545'}; border-radius: 50%; margin-right: 10px;"></div>
                <span style="color: white;">Account Status: </span>
                <span style="color: {'#28a745' if user.get('is_active') else '#dc3545'}; font-weight: 600; margin-left: 10px;">
                    {'✅ Active' if user.get('is_active') else '❌ Inactive'}
                </span>
            </div>
        """, unsafe_allow_html=True)
        
        # Stats cards
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("""
                <div style="background: linear-gradient(135deg, rgba(66, 135, 245, 0.1), rgba(103, 58, 183, 0.1)); border-radius: 10px; padding: 1rem; text-align: center;">
                    <span style="font-size: 2rem;">📊</span>
                    <h4 style="color: white; margin: 0.5rem 0 0 0;">{}</h4>
                    <p style="color: #a0a0a0; margin: 0;">Total Scans</p>
                </div>
            """.format(scan_stats.get('total_scans', 0)), unsafe_allow_html=True)
        
        with col_b:
            st.markdown("""
                <div style="background: linear-gradient(135deg, rgba(220, 53, 69, 0.1), rgba(176, 14, 33, 0.1)); border-radius: 10px; padding: 1rem; text-align: center;">
                    <span style="font-size: 2rem;">🔴</span>
                    <h4 style="color: white; margin: 0.5rem 0 0 0;">{}</h4>
                    <p style="color: #a0a0a0; margin: 0;">Vulnerabilities</p>
                </div>
            """.format(scan_stats.get('total_vulns', 0)), unsafe_allow_html=True)
    
    # Password change section
    st.markdown("---")
    change_password_ui()


def render_logout_button():
    """Render logout button in sidebar with enhanced UI"""
    if is_authenticated():
        user = get_current_user()
        
        # User profile card in sidebar
        st.sidebar.markdown("""
            <div style="background: linear-gradient(135deg, rgba(66, 135, 245, 0.2), rgba(103, 58, 183, 0.2)); border-radius: 10px; padding: 1rem; margin-bottom: 1rem; border: 1px solid rgba(66, 135, 245, 0.3);">
                <div style="display: flex; align-items: center;">
                    <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #4287f5, #673AB7); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 10px;">
                        <span style="color: white; font-weight: 600; font-size: 1.2rem;">{}</span>
                    </div>
                    <div>
                        <p style="color: white; margin: 0; font-weight: 600;">{}</p>
                        <p style="color: #a0a0a0; margin: 0; font-size: 0.8rem;">{}</p>
                    </div>
                </div>
            </div>
        """.format(
            user['username'][0].upper(),
            user['username'],
            user['role'].title()
        ), unsafe_allow_html=True)
        
        # Logout button
        if st.sidebar.button("🚪 Logout", use_container_width=True):
            with st.spinner("Logging out..."):
                logout()
                st.rerun()
        
        return True
    return False


def change_password_ui():
    """Render change password interface with enhanced UI"""
    st.markdown("""
        <div style="background: rgba(15, 12, 41, 0.95); backdrop-filter: blur(10px); border-radius: 15px; border: 1px solid rgba(66, 135, 245, 0.3); padding: 1.5rem; margin-top: 2rem;">
            <h3 style="color: #4287f5; margin-bottom: 1rem;">🔐 Change Password</h3>
    """, unsafe_allow_html=True)
    
    user = get_current_user()
    if not user:
        st.error("You must be logged in to change password")
        st.markdown("</div>", unsafe_allow_html=True)
        return False
    
    with st.form("change_password_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            old_password = st.text_input(
                "Current Password", 
                type="password",
                placeholder="Enter current password"
            )
        
        with col2:
            new_password = st.text_input(
                "New Password", 
                type="password",
                placeholder="Enter new password"
            )
        
        confirm_password = st.text_input(
            "Confirm New Password", 
            type="password",
            placeholder="Confirm new password"
        )
        
        # Password strength indicator
        if new_password:
            render_password_strength_indicator(new_password)
        
        col_a, col_b = st.columns(2)
        
        with col_a:
            submitted = st.form_submit_button(
                "✅ Update Password", 
                type="primary", 
                use_container_width=True
            )
        
        with col_b:
            if st.form_submit_button("✖️ Cancel", use_container_width=True):
                st.markdown("</div>", unsafe_allow_html=True)
                return False
        
        if submitted:
            if not old_password or not new_password or not confirm_password:
                st.error("❌ Please fill in all fields")
                return False
            
            if new_password != confirm_password:
                st.error("❌ New passwords do not match")
                return False
            
            with st.spinner("Updating password..."):
                success, message = change_user_password(user['id'], old_password, new_password)
                if success:
                    st.success(f"✅ {message}")
                    
                    # Create new session
                    new_token = SessionDB.create_session(
                        user_id=user['id'],
                        ip_address=_get_client_ip(),
                        user_agent=_get_user_agent()
                    )
                    st.session_state['session_token'] = new_token
                    
                    st.markdown("</div>", unsafe_allow_html=True)
                    return True
                else:
                    st.error(f"❌ {message}")
    
    st.markdown("</div>", unsafe_allow_html=True)
    return False


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def _get_client_ip() -> Optional[str]:
    """Get client IP address from Streamlit context"""
    try:
        headers = st.context.headers if hasattr(st, 'context') else {}
        ip = headers.get('x-forwarded-for', headers.get('remote-addr', None))
        if ip:
            return ip.split(',')[0].strip()
    except:
        pass
    return None


def _get_user_agent() -> Optional[str]:
    """Get user agent from Streamlit context"""
    try:
        headers = st.context.headers if hasattr(st, 'context') else {}
        return headers.get('user-agent', None)
    except:
        return None


def check_maintenance_mode():
    """Check if system is in maintenance mode and user is not admin"""
    user = get_current_user()
    
    if SystemSettingsDB.is_maintenance_mode():
        if not user or user.get('role') != 'admin':
            # Apply auth styling for maintenance page
            apply_auth_styling()
            render_auth_background()
            
            # Center container
            col1, col2, col3 = st.columns([1, 2, 1])
            
            with col2:
                st.markdown("""
                    <div class="auth-container" style="text-align: center;">
                        <div style="font-size: 4rem; margin-bottom: 1rem;">🚧</div>
                        <h1 style="color: #ffc107;">System Under Maintenance</h1>
                        <p style="color: #a0a0a0; margin: 1rem 0;">
                            The system is currently undergoing scheduled maintenance.
                            Please try again later. We apologize for the inconvenience.
                        </p>
                        <div style="background: rgba(255, 193, 7, 0.1); border-radius: 8px; padding: 1rem; margin-top: 1rem;">
                            <p style="color: #ffc107; margin: 0;">
                                ⏰ Expected completion: In a few minutes
                            </p>
                        </div>
                    </div>
                """, unsafe_allow_html=True)
            
            st.stop()


def require_auth(required_role: str = None):
    """
    Decorator alias for auth_guard
    """
    return auth_guard(required_role)


def require_admin(func):
    """
    Decorator specifically for admin-only access
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not is_admin():
            st.error("⛔ Access denied. Admin privileges required.")
            st.stop()
        return func(*args, **kwargs)
    return wrapper


# ============================================================================
# MAIN AUTH INTERFACE
# ============================================================================

def render_auth_interface():
    """Render the complete authentication interface"""
    # Initialize auth if not already initialized
    init_auth()
    
    # Check maintenance mode
    check_maintenance_mode()
    
    # Apply global auth styling
    apply_auth_styling()
    render_auth_background()
    
    # Check if user is already logged in
    if is_authenticated():
        return get_current_user()
    
    # Determine which page to show
    page = st.session_state.get('page', 'login')
    
    if page == 'register':
        return render_register_page()
    elif page == 'forgot_password':
        return render_forgot_password_page()
    else:  # default to login
        return render_login_page()

def with_cyber_loading(message=None):
    """Decorator for cybersecurity themed loading"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            loading = show_cyber_loading(
                message or func.__name__.replace('_', ' ').upper(),
                "Processing request..."
            )
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                loading.empty()
        return wrapper
    return decorator
# ============================================================================
# DATABASE INTEGRITY
# ============================================================================

def ensure_admin_exists():
    """Ensure admin user exists - call at startup"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE role = 'admin'")
        if not cursor.fetchone():
            # Create default admin
            try:
                import bcrypt
                password_hash = bcrypt.hashpw("Admin123!".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, full_name, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', ('admin', 'admin@securityscanner.com', password_hash, 'System Administrator', 'admin', datetime.now().isoformat()))
                conn.commit()
                print("✅ Default admin user created successfully")
                print("   Username: admin")
                print("   Password: Admin123!")
                print("   Email: admin@securityscanner.com")
                print("   ⚠️ Please change this password after first login!")
            except Exception as e:
                print(f"❌ Error creating admin: {e}")
