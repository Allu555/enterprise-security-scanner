# ============================================================================
# admin.py - Admin Dashboard
# ============================================================================

import os
import json
import shutil
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta

from database import (
    UserDB,
    ActivityLog,
    SessionDB,
    ScanHistoryDB,
    SystemSettingsDB,
    get_db_connection,
    DB_PATH
)

from auth import get_current_user, require_auth


# ----------------------------------------------------------------------------
# MAIN DASHBOARD
# ----------------------------------------------------------------------------
def render_admin_dashboard():
    """Main admin dashboard with system overview"""
    # Check if user is admin
    current_user = get_current_user()
    if not current_user or current_user.get('role') != 'admin':
        st.error("⛔ Access denied. Admin privileges required.")
        st.stop()
    
    # Header with gradient background
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 30px; border-radius: 15px; margin-bottom: 30px;">
        <h1 style="color: white; margin: 0;">👑 Admin Dashboard</h1>
        <p style="color: rgba(255,255,255,0.8); margin-top: 10px;">
            System Overview & User Management
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Get system statistics
    stats = ActivityLog.get_system_stats()

    # Display metrics in columns
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Users",
            value=stats.get("total_users", 0),
            delta=f"{stats.get('active_users_24h', 0)} active today"
        )
    
    with col2:
        st.metric(
            label="Total Scans",
            value=stats.get("total_scans", 0),
            delta=f"{stats.get('total_vulnerabilities', 0)} vulns found"
        )
    
    with col3:
        st.metric(
            label="Failed Logins (24h)",
            value=stats.get("failed_logins_24h", 0),
            delta="⚠️" if stats.get("failed_logins_24h", 0) > 10 else "✓",
            delta_color="inverse"
        )
    
    with col4:
        st.metric(
            label="System Status",
            value="ONLINE",
            delta="✅"
        )

    st.markdown("---")

    # Main tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["👥 User Management", 
         "📊 Scan History", 
         "📝 Activity Logs", 
         "🔐 Session Management",
         "⚙️ System Settings"]
    )

    with tab1:
        render_user_management()
    with tab2:
        render_scan_management()
    with tab3:
        render_activity_logs()
    with tab4:
        render_session_management()
    with tab5:
        render_system_settings()


# ----------------------------------------------------------------------------
# USER MANAGEMENT - COMPLETELY REWRITTEN
# ----------------------------------------------------------------------------
def render_user_management():
    """Complete user management interface"""
    st.subheader("👥 User Management")
    
    # Add new user section
    with st.expander("➕ Add New User", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            new_username = st.text_input("Username", key="new_username")
            new_email = st.text_input("Email", key="new_email")
            new_fullname = st.text_input("Full Name", key="new_fullname")
        
        with col2:
            new_password = st.text_input("Password", type="password", key="new_password")
            new_password_confirm = st.text_input("Confirm Password", type="password", key="new_password_confirm")
            new_role = st.selectbox("Role", ["user", "admin"], key="new_role")
        
        if st.button("Create User", type="primary", use_container_width=True):
            if not new_username or not new_email or not new_password:
                st.error("❌ Username, email, and password are required")
            elif new_password != new_password_confirm:
                st.error("❌ Passwords do not match")
            else:
                try:
                    user = UserDB.create_user(
                        username=new_username,
                        email=new_email,
                        password=new_password,
                        full_name=new_fullname,
                        role=new_role
                    )
                    
                    # Log the action
                    current_admin = get_current_user()
                    ActivityLog.log(
                        user_id=current_admin['id'],
                        username=current_admin['username'],
                        action="user_created",
                        resource_type="user",
                        resource_id=str(user['id']),
                        details={"username": new_username, "role": new_role},
                        status="success"
                    )
                    
                    st.success(f"✅ User {new_username} created successfully!")
                    st.rerun()
                    
                except ValueError as e:
                    st.error(f"❌ {str(e)}")
                except Exception as e:
                    st.error(f"❌ Failed to create user: {str(e)}")

    # Get all users
    users = UserDB.get_all_users()
    
    if not users:
        st.info("📭 No users found in the system")
        return
    
    # Convert to DataFrame for display
    df = pd.DataFrame(users)
    
    # Format datetime columns
    if "created_at" in df.columns:
        df["created_at"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:%M")
    if "last_login" in df.columns:
        df["last_login"] = pd.to_datetime(df["last_login"]).dt.strftime("%Y-%m-%d %H:%M")
    
    # Add status column
    df["status"] = df.apply(
        lambda row: "✅ Active" if row["is_active"] else "⛔ Blocked", 
        axis=1
    )
    
    # Add lock status
    df["lock_status"] = df.apply(
        lambda row: "🔒 Locked" if row.get("locked_until") and 
                    datetime.fromisoformat(row["locked_until"]) > datetime.now() 
                    else "✓ Unlocked",
        axis=1
    )
    
    # Display user table with selection
    st.dataframe(
        df[["id", "username", "email", "full_name", "role", "status", "lock_status", 
            "created_at", "last_login", "failed_attempts"]],
        use_container_width=True,
        column_config={
            "id": "ID",
            "username": "Username",
            "email": "Email",
            "full_name": "Full Name",
            "role": "Role",
            "status": "Status",
            "lock_status": "Lock Status",
            "created_at": "Created",
            "last_login": "Last Login",
            "failed_attempts": "Failed Attempts"
        }
    )
    
    st.markdown("---")
    st.subheader("🛠️ User Actions")
    
    current_admin = get_current_user()
    
    # User selection for actions
    selected_user = st.selectbox(
        "Select User for Action",
        users,
        format_func=lambda u: f"{u['username']} ({u['email']}) - {u['role']} - {'Active' if u['is_active'] else 'Blocked'}",
        key="user_select"
    )
    
    # Action selection
    action = st.radio(
        "Choose Action",
        [
            "Block/Unblock User",
            "Promote/Demote Admin",
            "Reset Password",
            "Unlock Account",
            "View User Details",
            "Delete User"
        ],
        horizontal=True
    )
    
    # Execute selected action
    if action == "Block/Unblock User":
        render_block_unblock(selected_user, current_admin)
    
    elif action == "Promote/Demote Admin":
        render_role_change(selected_user, current_admin)
    
    elif action == "Reset Password":
        render_password_reset(selected_user, current_admin)
    
    elif action == "Unlock Account":
        render_unlock_account(selected_user, current_admin)
    
    elif action == "View User Details":
        render_user_details(selected_user)
    
    elif action == "Delete User":
        render_user_deletion(selected_user, current_admin)


def render_block_unblock(user, admin):
    """Block or unblock a user"""
    st.info(f"Current status: {'✅ Active' if user['is_active'] else '⛔ Blocked'}")
    
    new_status = 0 if user["is_active"] else 1
    action_label = "Unblock" if not user["is_active"] else "Block"
    button_type = "secondary" if action_label == "Unblock" else "primary"
    
    if st.button(f"{action_label} User", type=button_type, use_container_width=True):
        try:
            # Prevent admin from blocking themselves
            if user["id"] == admin["id"] and action_label == "Block":
                st.error("❌ You cannot block your own account!")
                return
            
            UserDB.update_user(user["id"], is_active=new_status)
            
            # Log the action
            ActivityLog.log(
                user_id=admin["id"],
                username=admin["username"],
                action="user_status_change",
                resource_type="user",
                resource_id=str(user["id"]),
                details={
                    "target_user": user["username"],
                    "new_status": "active" if new_status else "blocked"
                },
                status="success"
            )
            
            # Invalidate sessions if blocking
            if new_status == 0:
                SessionDB.invalidate_all_user_sessions(user["id"])
            
            st.success(f"✅ User {user['username']} {action_label.lower()}ed successfully")
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Failed to update user: {str(e)}")


def render_role_change(user, admin):
    """Change user role between admin and user"""
    if user["id"] == admin["id"]:
        st.warning("⚠️ You cannot change your own role.")
        return
    
    current_role = user["role"]
    new_role = "admin" if current_role != "admin" else "user"
    
    st.info(f"Current role: **{current_role.upper()}**")
    st.warning(f"New role will be: **{new_role.upper()}**")
    
    if st.button(f"Change Role to {new_role.title()}", type="primary", use_container_width=True):
        try:
            UserDB.update_user(user["id"], role=new_role)
            
            # Log the action
            ActivityLog.log(
                user_id=admin["id"],
                username=admin["username"],
                action="role_change",
                resource_type="user",
                resource_id=str(user["id"]),
                details={
                    "target_user": user["username"],
                    "old_role": current_role,
                    "new_role": new_role
                },
                status="success"
            )
            
            st.success(f"✅ User {user['username']} role changed to {new_role}")
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Failed to change role: {str(e)}")


def render_password_reset(user, admin):
    """Reset user password"""
    st.warning(f"⚠️ Resetting password for: **{user['username']}**")
    
    col1, col2 = st.columns(2)
    
    with col1:
        new_password = st.text_input("New Password", type="password", key="reset_pass")
    with col2:
        confirm_password = st.text_input("Confirm Password", type="password", key="reset_pass_confirm")
    
    if st.button("Reset Password", type="primary", use_container_width=True):
        if not new_password or len(new_password) < 6:
            st.error("❌ Password must be at least 6 characters")
        elif new_password != confirm_password:
            st.error("❌ Passwords do not match")
        else:
            try:
                # Direct password reset by admin
                UserDB.admin_reset_password(user["id"], new_password)
                
                # Invalidate all sessions
                SessionDB.invalidate_all_user_sessions(user["id"])
                
                # Log the action
                ActivityLog.log(
                    user_id=admin["id"],
                    username=admin["username"],
                    action="password_reset",
                    resource_type="user",
                    resource_id=str(user["id"]),
                    details={"target_user": user["username"]},
                    status="success"
                )
                
                st.success(f"✅ Password reset successfully for {user['username']}")
                
            except Exception as e:
                st.error(f"❌ Failed to reset password: {str(e)}")


def render_unlock_account(user, admin):
    """Unlock a locked user account"""
    locked_until = user.get("locked_until")
    
    if not locked_until:
        st.info("✅ Account is not locked")
        return
    
    try:
        lock_time = datetime.fromisoformat(locked_until)
        if lock_time <= datetime.now():
            st.info("✅ Account lock has expired")
            return
    except:
        st.info("✅ Account is not locked")
        return
    
    st.warning(f"🔒 Account is locked until: {lock_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    if st.button("Unlock Account", type="primary", use_container_width=True):
        try:
            UserDB.unlock_user_account(user["id"])
            
            # Log the action
            ActivityLog.log(
                user_id=admin["id"],
                username=admin["username"],
                action="account_unlocked",
                resource_type="user",
                resource_id=str(user["id"]),
                details={"target_user": user["username"]},
                status="success"
            )
            
            st.success(f"✅ Account unlocked for {user['username']}")
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Failed to unlock account: {str(e)}")


def render_user_details(user):
    """Display detailed user information"""
    st.subheader(f"📋 User Details: {user['username']}")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Basic Information**")
        st.write(f"**ID:** {user['id']}")
        st.write(f"**Username:** {user['username']}")
        st.write(f"**Email:** {user['email']}")
        st.write(f"**Full Name:** {user.get('full_name', 'N/A')}")
        st.write(f"**Role:** {user['role']}")
    
    with col2:
        st.markdown("**Account Status**")
        st.write(f"**Active:** {'✅ Yes' if user['is_active'] else '❌ No'}")
        st.write(f"**Failed Attempts:** {user.get('failed_attempts', 0)}")
        
        locked_until = user.get("locked_until")
        if locked_until:
            try:
                lock_time = datetime.fromisoformat(locked_until)
                st.write(f"**Locked Until:** {lock_time.strftime('%Y-%m-%d %H:%M:%S')}")
            except:
                pass
        
        st.write(f"**Created:** {user.get('created_at', 'N/A')}")
        st.write(f"**Last Login:** {user.get('last_login', 'Never')}")
    
    # Get user activity
    st.subheader("📊 Recent Activity")
    activities = ActivityLog.get_user_activity(user['id'], limit=10)
    
    if activities:
        for act in activities[:5]:
            st.markdown(f"- **{act['created_at']}**: {act['action']} - {act['status']}")
    else:
        st.info("No recent activity")


def render_user_deletion(user, admin):
    """Delete a user from the system"""
    if user["id"] == admin["id"]:
        st.error("❌ You cannot delete your own account!")
        return
    
    st.error(f"⚠️ **DANGER ZONE** - Deleting user: {user['username']}")
    
    confirm = st.checkbox("I understand this action is irreversible and will delete all user data")
    confirm_name = st.text_input("Type the username to confirm deletion:")
    
    if st.button("🗑️ Delete User Permanently", type="primary", use_container_width=True):
        if not confirm:
            st.error("❌ Please confirm that you understand the consequences")
        elif confirm_name != user['username']:
            st.error("❌ Username confirmation does not match")
        else:
            try:
                UserDB.delete_user(user["id"])
                
                # Log the action
                ActivityLog.log(
                    user_id=admin["id"],
                    username=admin["username"],
                    action="user_deleted",
                    resource_type="user",
                    resource_id=str(user["id"]),
                    details={"target_user": user["username"]},
                    status="success"
                )
                
                st.success(f"✅ User {user['username']} has been deleted")
                st.rerun()
                
            except Exception as e:
                st.error(f"❌ Failed to delete user: {str(e)}")


# ----------------------------------------------------------------------------
# SCAN MANAGEMENT
# ----------------------------------------------------------------------------
def render_scan_management():
    """Global scan history management"""
    st.subheader("📊 Global Scan History")
    
    # Date filter
    col1, col2 = st.columns(2)
    with col1:
        date_range = st.selectbox(
            "Time Range",
            ["Last 24 hours", "Last 7 days", "Last 30 days", "All time"],
            key="scan_date_range"
        )
    
    with col2:
        status_filter = st.multiselect(
            "Status",
            ["completed", "running", "failed", "stopped"],
            default=["completed"],
            key="scan_status_filter"
        )
    
    # Get scan data
    scans = ScanHistoryDB.get_all_scans(limit=1000)
    
    if not scans:
        st.info("📭 No scan history available")
        return
    
    df = pd.DataFrame(scans)
    df["start_time"] = pd.to_datetime(df["start_time"])
    
    # Apply filters
    if date_range == "Last 24 hours":
        df = df[df["start_time"] > datetime.now() - timedelta(days=1)]
    elif date_range == "Last 7 days":
        df = df[df["start_time"] > datetime.now() - timedelta(days=7)]
    elif date_range == "Last 30 days":
        df = df[df["start_time"] > datetime.now() - timedelta(days=30)]
    
    if status_filter:
        df = df[df["status"].isin(status_filter)]
    
    # Display metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Scans", len(df))
    with col2:
        st.metric("Total Vulnerabilities", df["vulnerabilities_found"].sum())
    with col3:
        st.metric("Avg Risk Score", f"{df['risk_score'].mean():.1f}%" if len(df) > 0 else "0%")
    with col4:
        high_risk = len(df[df['risk_score'] >= 70])
        st.metric("High Risk Scans", high_risk, delta="⚠️" if high_risk > 0 else "✓")
    
    # Visualization
    if len(df) > 0:
        fig = px.line(
            df.sort_values("start_time"),
            x="start_time",
            y="vulnerabilities_found",
            color="username" if len(df["username"].unique()) <= 10 else None,
            title="Vulnerability Detection Trend"
        )
        
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Display scan table
    st.subheader("Scan Records")
    
    display_df = df[["username", "target_url", "start_time", 
                     "vulnerabilities_found", "risk_score", "status"]].copy()
    
    display_df["start_time"] = display_df["start_time"].dt.strftime("%Y-%m-%d %H:%M")
    display_df["risk_score"] = display_df["risk_score"].round(1).astype(str) + "%"
    
    st.dataframe(
        display_df,
        use_container_width=True,
        column_config={
            "username": "User",
            "target_url": "Target",
            "start_time": "Scan Time",
            "vulnerabilities_found": "Vulnerabilities",
            "risk_score": "Risk Score",
            "status": "Status"
        }
    )
    
    # Export option
    if st.button("📥 Export Scan Data", use_container_width=True):
        csv = display_df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"scan_export_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv"
        )


# ----------------------------------------------------------------------------
# ACTIVITY LOGS
# ----------------------------------------------------------------------------
def render_activity_logs():
    """System activity logs viewer"""
    st.subheader("📝 System Activity Logs")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        action_filter = st.text_input("Filter by Action", placeholder="e.g., login, scan...")
    
    with col2:
        user_filter = st.text_input("Filter by Username", placeholder="Username...")
    
    with col3:
        status_filter = st.selectbox(
            "Status",
            ["All", "success", "failed", "warning"],
            key="log_status_filter"
        )
    
    # Get logs
    logs = ActivityLog.get_all_activity(limit=500)
    
    if not logs:
        st.info("📭 No activity logs found")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(logs)
    df["created_at"] = pd.to_datetime(df["created_at"])
    
    # Apply filters
    if action_filter:
        df = df[df["action"].str.contains(action_filter, case=False, na=False)]
    
    if user_filter:
        df = df[df["username"].str.contains(user_filter, case=False, na=False)]
    
    if status_filter != "All":
        df = df[df["status"] == status_filter]
    
    # Display logs
    st.metric("Total Logs", len(df))
    
    for _, log in df.head(100).iterrows():
        time_str = log['created_at'].strftime("%Y-%m-%d %H:%M:%S")
        
        # Color code by status
        if log['status'] == 'success':
            color = '#28a745'
        elif log['status'] == 'failed':
            color = '#dc3545'
        elif log['status'] == 'warning':
            color = '#ffc107'
        else:
            color = '#6c757d'
        
        st.markdown(
            f"""
            <div style="padding: 10px; margin: 5px 0; background: rgba(255,255,255,0.05); 
                        border-left: 4px solid {color}; border-radius: 4px;">
                <span style="color: #888;">{time_str}</span><br>
                <strong>@{log['username']}</strong> — <code>{log['action']}</code><br>
                <span style="color: {color};">{log['status']}</span>
            </div>
            """,
            unsafe_allow_html=True
        )


# ----------------------------------------------------------------------------
# SESSION MANAGEMENT
# ----------------------------------------------------------------------------
def render_session_management():
    """Active session management"""
    st.subheader("🔐 Active Sessions")
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT s.*, u.username, u.email 
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.is_valid = 1 AND s.expires_at > ?
            ORDER BY s.created_at DESC
            LIMIT 100
        ''', (datetime.now().isoformat(),))
        
        sessions = [dict(row) for row in cursor.fetchall()]
    
    if not sessions:
        st.info("📭 No active sessions")
        return
    
    df = pd.DataFrame(sessions)
    df["created_at"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:%M")
    df["expires_at"] = pd.to_datetime(df["expires_at"]).dt.strftime("%Y-%m-%d %H:%M")
    
    st.dataframe(
        df[["username", "email", "ip_address", "created_at", "expires_at"]],
        use_container_width=True,
        column_config={
            "username": "User",
            "email": "Email",
            "ip_address": "IP Address",
            "created_at": "Created",
            "expires_at": "Expires"
        }
    )
    
    # Session controls
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🚫 Invalidate All Sessions", type="primary", use_container_width=True):
            with get_db_connection() as conn:
                conn.execute("UPDATE sessions SET is_valid = 0 WHERE is_valid = 1")
            st.success("✅ All sessions have been invalidated")
            st.rerun()
    
    with col2:
        if st.button("🧹 Clean Expired Sessions", use_container_width=True):
            with get_db_connection() as conn:
                conn.execute("DELETE FROM sessions WHERE expires_at <= ?", 
                           (datetime.now().isoformat(),))
            st.success("✅ Expired sessions cleaned")
            st.rerun()


# ----------------------------------------------------------------------------
# SYSTEM SETTINGS
# ----------------------------------------------------------------------------
def render_system_settings():
    """System configuration settings"""
    st.subheader("⚙️ System Settings")
    
    # Database information
    with st.expander("📁 Database Management", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            if os.path.exists(DB_PATH):
                db_size = os.path.getsize(DB_PATH) / (1024 * 1024)
                st.metric("Database Size", f"{db_size:.2f} MB")
                
                if st.button("🔄 Optimize Database", use_container_width=True):
                    with get_db_connection() as conn:
                        conn.execute("VACUUM")
                    st.success("✅ Database optimized successfully")
            
            if st.button("📊 Database Statistics", use_container_width=True):
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute("SELECT COUNT(*) FROM users")
                    user_count = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM scan_history")
                    scan_count = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM activity_logs")
                    log_count = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM sessions")
                    session_count = cursor.fetchone()[0]
                
                st.info(f"""
                **Database Statistics:**
                - Users: {user_count}
                - Scans: {scan_count}
                - Activity Logs: {log_count}
                - Active Sessions: {session_count}
                """)
        
        with col2:
            st.metric("Last Backup", "Not available")
            
            if st.button("💾 Backup Database", use_container_width=True):
                backup_dir = "backups"
                os.makedirs(backup_dir, exist_ok=True)
                
                backup_path = os.path.join(
                    backup_dir,
                    f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
                )
                
                try:
                    shutil.copy2(DB_PATH, backup_path)
                    st.success(f"✅ Backup created: {os.path.basename(backup_path)}")
                    
                    # Log backup action
                    current_admin = get_current_user()
                    ActivityLog.log(
                        user_id=current_admin['id'],
                        username=current_admin['username'],
                        action="database_backup",
                        status="success",
                        details={"backup_path": backup_path}
                    )
                except Exception as e:
                    st.error(f"❌ Backup failed: {str(e)}")
    
    # System configuration
    with st.expander("⚙️ System Configuration", expanded=True):
        settings = SystemSettingsDB.get_all_settings()
        
        col1, col2 = st.columns(2)
        
        with col1:
            max_scan_duration = st.number_input(
                "Max Scan Duration (seconds)",
                min_value=60,
                max_value=7200,
                value=int(settings.get('max_scan_duration', 3600)),
                help="Maximum time allowed for a single scan (60-7200 seconds)"
            )
            
            max_pages = st.number_input(
                "Max Pages per Scan",
                min_value=10,
                max_value=500,
                value=int(settings.get('max_pages_per_scan', 100)),
                help="Maximum number of pages to crawl per scan"
            )
        
        with col2:
            # Handle backward compatibility - convert seconds to hours if needed
            session_timeout_value = settings.get('session_timeout', 24)
            try:
                session_timeout_int = int(session_timeout_value)
                # If it's a large number (seconds format), convert to hours
                if session_timeout_int > 72:  # Assume seconds if > 72
                    session_timeout_hours = session_timeout_int // 3600
                    # Clamp to valid range
                    session_timeout_hours = max(1, min(72, session_timeout_hours))
                else:
                    session_timeout_hours = session_timeout_int
            except (ValueError, TypeError):
                session_timeout_hours = 24
            
            session_timeout = st.number_input(
                "Session Timeout (hours)",
                min_value=1,
                max_value=72,
                value=session_timeout_hours,
                help="User session duration in hours (1-72 hours)"
            )
            
            enable_ai = st.checkbox(
                "Enable AI Analysis",
                value=settings.get('enable_ai_analysis', 'true').lower() == 'true',
                help="Enable Ollama AI-powered vulnerability analysis"
            )
        
        registration_enabled = st.checkbox(
            "Allow User Registration",
            value=settings.get('registration_enabled', 'true').lower() == 'true',
            help="Allow new users to register accounts"
        )
        
        maintenance_mode = st.checkbox(
            "Maintenance Mode",
            value=settings.get('maintenance_mode', 'false').lower() == 'true',
            help="When enabled, only admins can access the system"
        )
        
        # Add notification settings
        st.markdown("---")
        st.markdown("#### 📧 Notification Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            email_notifications = st.checkbox(
                "Enable Email Notifications",
                value=settings.get('email_notifications', 'false').lower() == 'true',
                help="Send email notifications for scan completions and security alerts"
            )
        
        with col2:
            if email_notifications:
                notification_email = st.text_input(
                    "Notification Email",
                    value=settings.get('notification_email', ''),
                    placeholder="admin@example.com",
                    help="Email address to receive notifications"
                )
            else:
                notification_email = settings.get('notification_email', '')
        
        # Save button with confirmation
        if st.button("💾 Save All Settings", type="primary", use_container_width=True):
            current_admin = get_current_user()
            
            try:
                # Save basic settings
                SystemSettingsDB.set_setting('max_scan_duration', str(max_scan_duration), current_admin['id'])
                SystemSettingsDB.set_setting('max_pages_per_scan', str(max_pages), current_admin['id'])
                SystemSettingsDB.set_setting('session_timeout', str(session_timeout), current_admin['id'])
                SystemSettingsDB.set_setting('enable_ai_analysis', str(enable_ai).lower(), current_admin['id'])
                SystemSettingsDB.set_setting('registration_enabled', str(registration_enabled).lower(), current_admin['id'])
                SystemSettingsDB.set_setting('maintenance_mode', str(maintenance_mode).lower(), current_admin['id'])
                
                # Save notification settings
                SystemSettingsDB.set_setting('email_notifications', str(email_notifications).lower(), current_admin['id'])
                if email_notifications and notification_email:
                    SystemSettingsDB.set_setting('notification_email', notification_email, current_admin['id'])
                
                st.success("✅ All settings saved successfully!")
                
                # Show warning if maintenance mode is enabled
                if maintenance_mode:
                    st.warning("⚠️ Maintenance mode is ON. Regular users cannot access the system.")
                
                # Show registration status
                if not registration_enabled:
                    st.info("📝 User registration is disabled.")
                
                # Force rerun to reflect changes
                st.rerun()
                
            except Exception as e:
                st.error(f"❌ Failed to save settings: {str(e)}")
    
    # System Information
    with st.expander("ℹ️ System Information", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Application Info**")
            st.write(f"- **Version:** 1.0.0")
            st.write(f"- **Python:** {os.sys.version.split()[0]}")
            st.write(f"- **Streamlit:** {st.__version__}")
            st.write(f"- **Database:** SQLite 3")
        
        with col2:
            st.markdown("**System Resources**")
            try:
                import psutil
                st.write(f"- **CPU Usage:** {psutil.cpu_percent()}%")
                st.write(f"- **Memory Usage:** {psutil.virtual_memory().percent}%")
                st.write(f"- **Disk Usage:** {psutil.disk_usage('/').percent}%")
            except ImportError:
                st.write("- **CPU Usage:** psutil not installed")
                st.write("- **Memory Usage:** psutil not installed")
                st.write("- **Disk Usage:** psutil not installed")
    
    # Maintenance
    with st.expander("🧹 System Maintenance", expanded=False):
        st.warning("⚠️ These actions may affect system performance")
        
        col1, col2 = st.columns(2)
        
        with col1:
            days_to_keep = st.number_input(
                "Keep logs for (days)",
                min_value=1,
                max_value=365,
                value=30,
                help="Activity logs older than this will be deleted"
            )
            
            if st.button("🧹 Clean Old Logs", use_container_width=True):
                cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
                
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "DELETE FROM activity_logs WHERE created_at < ?",
                        (cutoff_date,)
                    )
                    deleted = cursor.rowcount
                
                st.success(f"✅ Deleted {deleted} old log entries")
        
        with col2:
            if st.button("🗑️ Clear Expired Sessions", use_container_width=True):
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "DELETE FROM sessions WHERE expires_at <= ?",
                        (datetime.now().isoformat(),)
                    )
                    deleted = cursor.rowcount
                
                st.success(f"✅ Cleared {deleted} expired sessions")
            
            if st.button("📊 Analyze Database", use_container_width=True):
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("ANALYZE")
                st.success("✅ Database analysis completed")
    
    # Danger Zone
    with st.expander("⚠️ Danger Zone", expanded=False):
        st.error("⚠️ These actions are irreversible and should be used with caution!")
        
        col1, col2 = st.columns(2)
        
        with col1:
            reset_confirm = st.checkbox("I understand this will delete ALL scan history")
            
            if st.button("🗑️ Reset All Scan Data", type="primary", use_container_width=True):
                if reset_confirm:
                    with get_db_connection() as conn:
                        conn.execute("DELETE FROM scan_history")
                        conn.execute("DELETE FROM vulnerabilities")
                    
                    current_admin = get_current_user()
                    ActivityLog.log(
                        user_id=current_admin['id'],
                        username=current_admin['username'],
                        action="system_reset",
                        status="success",
                        details={"reset_type": "scan_data"}
                    )
                    
                    st.success("✅ All scan data has been deleted")
                    st.rerun()
                else:
                    st.error("❌ Please confirm the action")
        
        with col2:
            factory_confirm = st.checkbox("I understand this will reset the ENTIRE system")
            factory_confirm2 = st.checkbox("I have a backup of all important data")
            
            if st.button("🏭 Factory Reset", type="primary", use_container_width=True):
                if factory_confirm and factory_confirm2:
                    with get_db_connection() as conn:
                        # Keep users but reset everything else
                        conn.execute("DELETE FROM scan_history")
                        conn.execute("DELETE FROM vulnerabilities")
                        conn.execute("DELETE FROM activity_logs")
                        conn.execute("DELETE FROM sessions")
                        conn.execute("DELETE FROM system_settings WHERE setting_key NOT IN ('registration_enabled', 'maintenance_mode')")
                    
                    st.success("✅ System has been reset to factory defaults")
                    st.warning("⚠️ Please log in again")
                    
                    from auth import logout
                    logout()
                else:
                    st.error("❌ Please confirm both checkboxes")
