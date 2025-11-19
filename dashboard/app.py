#!/usr/bin/env python3
"""
Interactive Security Dashboard
Visualizes vulnerability scans, ML predictions, and alerts
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import psycopg2
from datetime import datetime, timedelta
import os

# Page configuration
st.set_page_config(
    page_title="Container Security Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Database connection
def get_db_connection():
    """Create database connection"""
    return psycopg2.connect(
        host=os.getenv('DB_HOST', 'postgres'),
        port=os.getenv('DB_PORT', '5432'),
        database=os.getenv('DB_NAME', 'security_db'),
        user=os.getenv('DB_USER', 'security_user'),
        password=os.getenv('DB_PASSWORD', 'security_pass')
    )

def load_latest_scans(limit=10):
    """Load latest scan results"""
    conn = get_db_connection()
    query = """
        SELECT 
            sr.scan_id,
            sr.image_name,
            sr.image_tag,
            sr.scan_timestamp,
            sr.total_vulnerabilities,
            sr.critical_count,
            sr.high_count,
            sr.medium_count,
            sr.low_count,
            mp.risk_score,
            mp.risk_category,
            mp.is_anomaly
        FROM scan_results sr
        LEFT JOIN ml_predictions mp ON sr.scan_id = mp.scan_id
        ORDER BY sr.scan_timestamp DESC
        LIMIT %s
    """
    df = pd.read_sql_query(query, conn, params=(limit,))
    conn.close()
    return df

def load_vulnerability_trends(days=30):
    """Load vulnerability trends over time"""
    conn = get_db_connection()
    query = """
        SELECT 
            DATE(scan_timestamp) as date,
            AVG(total_vulnerabilities) as avg_vulns,
            AVG(critical_count) as avg_critical,
            AVG(high_count) as avg_high,
            COUNT(*) as scan_count
        FROM scan_results
        WHERE scan_timestamp > NOW() - INTERVAL '%s days'
        GROUP BY DATE(scan_timestamp)
        ORDER BY date
    """
    df = pd.read_sql_query(query, conn, params=(days,))
    conn.close()
    return df

def load_active_alerts():
    """Load active security alerts"""
    conn = get_db_connection()
    query = """
        SELECT 
            alert_id,
            alert_timestamp,
            alert_type,
            severity,
            title,
            description,
            status
        FROM security_alerts
        WHERE status IN ('open', 'acknowledged')
        ORDER BY alert_timestamp DESC
        LIMIT 20
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def load_scan_details(scan_id):
    """Load detailed scan information"""
    conn = get_db_connection()
    
    # Scan summary
    query1 = """
        SELECT * FROM scan_results WHERE scan_id = %s
    """
    scan_df = pd.read_sql_query(query1, conn, params=(scan_id,))
    
    # Vulnerabilities
    query2 = """
        SELECT 
            cve_id, package_name, installed_version, fixed_version,
            severity, cvss_score, description
        FROM vulnerabilities
        WHERE scan_id = %s
        ORDER BY 
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            cvss_score DESC NULLS LAST
    """
    vulns_df = pd.read_sql_query(query2, conn, params=(scan_id,))
    
    # ML Prediction
    query3 = """
        SELECT * FROM ml_predictions WHERE scan_id = %s
    """
    pred_df = pd.read_sql_query(query3, conn, params=(scan_id,))
    
    conn.close()
    return scan_df, vulns_df, pred_df

# Custom CSS
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
    }
    .alert-critical {
        background-color: #ff4b4b;
        color: white;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .alert-high {
        background-color: #ffa500;
        color: white;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .alert-medium {
        background-color: #ffeb3b;
        color: black;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
</style>
""", unsafe_allow_html=True)

# Main dashboard
def main():
    st.title("🔒 Container Security Dashboard")
    st.markdown("**ML-Powered Vulnerability Analysis & Anomaly Detection**")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Settings")
        
        refresh = st.button("🔄 Refresh Data")
        if refresh:
            st.cache_data.clear()
            st.cache_resource.clear()
            st.rerun()
        
        st.markdown("---")
        
        # Navigation
        page = st.radio(
            "Navigation",
            ["📊 Overview", "🔍 Scan Details", "🚨 Alerts", "📈 Analytics"]
        )
        
        st.markdown("---")
        st.markdown("**Quick Stats**")
        
        # Load quick stats
        try:
            df = load_latest_scans(100)
            st.metric("Total Scans", len(df))
            st.metric("Active Alerts", len(load_active_alerts()))
            if not df.empty:
                st.metric("Avg Risk Score", f"{df['risk_score'].mean():.1f}/100")
        except:
            st.warning("Unable to load stats")
    
    # Main content
    if page == "📊 Overview":
        show_overview()
    elif page == "🔍 Scan Details":
        show_scan_details()
    elif page == "🚨 Alerts":
        show_alerts()
    elif page == "📈 Analytics":
        show_analytics()

def show_overview():
    """Display overview dashboard"""
    st.header("Overview Dashboard")
    
    # Load data
    try:
        df = load_latest_scans(50)
        trends = load_vulnerability_trends(30)
        alerts = load_active_alerts()
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_vulns = df['total_vulnerabilities'].sum()
            st.metric("Total Vulnerabilities", f"{total_vulns:,}")
        
        with col2:
            critical = df['critical_count'].sum()
            st.metric("Critical", critical, delta=None, delta_color="inverse")
        
        with col3:
            anomalies = df['is_anomaly'].sum() if 'is_anomaly' in df.columns else 0
            st.metric("Anomalies Detected", anomalies)
        
        with col4:
            avg_risk = df['risk_score'].mean() if 'risk_score' in df.columns else 0
            st.metric("Avg Risk Score", f"{avg_risk:.1f}/100")
        
        st.markdown("---")
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Recent Scans")
            if not df.empty:
                # Risk score distribution
                fig = px.bar(
                    df.head(10),
                    x='image_name',
                    y='risk_score',
                    color='risk_category',
                    title="Risk Scores by Image",
                    color_discrete_map={
                        'critical': '#ff4b4b',
                        'high': '#ffa500',
                        'medium': '#ffeb3b',
                        'low': '#4caf50'
                    }
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No scan data available")
        
        with col2:
            st.subheader("Vulnerability Trends")
            if not trends.empty:
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=trends['date'], y=trends['avg_critical'],
                    name='Critical', line=dict(color='red', width=2)
                ))
                fig.add_trace(go.Scatter(
                    x=trends['date'], y=trends['avg_high'],
                    name='High', line=dict(color='orange', width=2)
                ))
                fig.update_layout(
                    title="30-Day Vulnerability Trend",
                    xaxis_title="Date",
                    yaxis_title="Average Count",
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No trend data available")
        
        # Recent scans table
        st.subheader("Latest Scans")
        if not df.empty:
            display_df = df[['scan_timestamp', 'image_name', 'image_tag', 
                           'total_vulnerabilities', 'critical_count', 'high_count',
                           'risk_score', 'risk_category']].head(10)
            display_df['scan_timestamp'] = pd.to_datetime(display_df['scan_timestamp']).dt.strftime('%Y-%m-%d %H:%M')
            st.dataframe(display_df, use_container_width=True, hide_index=True)
        
        # Active alerts
        if not alerts.empty:
            st.subheader("🚨 Active Alerts")
            for _, alert in alerts.head(5).iterrows():
                severity_class = f"alert-{alert['severity']}"
                st.markdown(
                    f"<div class='{severity_class}'>"
                    f"<strong>{alert['title']}</strong><br>"
                    f"{alert['description'][:200]}..."
                    f"</div>",
                    unsafe_allow_html=True
                )
    
    except Exception as e:
        st.error(f"Error loading dashboard data: {e}")

def show_scan_details():
    """Display detailed scan information"""
    st.header("Scan Details")
    
    try:
        # Scan selector
        df = load_latest_scans(100)
        if df.empty:
            st.info("No scans available. Run a scan first!")
            return
        
        scan_options = df.apply(
            lambda x: f"{x['image_name']}:{x['image_tag']} - {x['scan_timestamp']}",
            axis=1
        ).tolist()
        
        selected = st.selectbox("Select a scan", scan_options)
        selected_idx = scan_options.index(selected)
        scan_id = df.iloc[selected_idx]['scan_id']
        
        # Load details
        scan_df, vulns_df, pred_df = load_scan_details(scan_id)
        
        if scan_df.empty:
            st.error("Scan not found")
            return
        
        scan = scan_df.iloc[0]
        
        # Scan summary
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Vulnerabilities", scan['total_vulnerabilities'])
            st.metric("Critical", scan['critical_count'])
        with col2:
            st.metric("High", scan['high_count'])
            st.metric("Medium", scan['medium_count'])
        with col3:
            if not pred_df.empty:
                pred = pred_df.iloc[0]
                st.metric("Risk Score", f"{pred['risk_score']:.0f}/100")
                st.metric("Anomaly", "Yes" if pred['is_anomaly'] else "No")
        
        # ML Prediction
        if not pred_df.empty:
            st.subheader("🤖 ML Analysis")
            pred = pred_df.iloc[0]
            
            col1, col2 = st.columns([2, 1])
            with col1:
                st.markdown(f"**Risk Category:** {pred['risk_category'].upper()}")
                st.markdown(f"**Confidence:** {pred['confidence_score']:.2%}")
                if pred['is_anomaly']:
                    st.warning("⚠️ ANOMALY DETECTED - Unusual vulnerability pattern")
            
            with col2:
                # Risk gauge
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=pred['risk_score'],
                    title={'text': "Risk Score"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 40], 'color': "lightgreen"},
                            {'range': [40, 60], 'color': "yellow"},
                            {'range': [60, 80], 'color': "orange"},
                            {'range': [80, 100], 'color': "red"}
                        ]
                    }
                ))
                fig.update_layout(height=250)
                st.plotly_chart(fig, use_container_width=True)
            
            if 'recommendations' in pred and pred['recommendations']:
                st.markdown("**Recommendations:**")
                for rec in pred['recommendations']:
                    st.markdown(f"- {rec}")
        
        # Vulnerabilities table
        st.subheader("Vulnerabilities")
        if not vulns_df.empty:
            # Severity filter
            severities = st.multiselect(
                "Filter by severity",
                ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'],
                default=['CRITICAL', 'HIGH']
            )
            filtered = vulns_df[vulns_df['severity'].isin(severities)]
            
            st.dataframe(
                filtered[['cve_id', 'package_name', 'installed_version', 
                         'fixed_version', 'severity', 'cvss_score']],
                use_container_width=True,
                hide_index=True
            )
        else:
            st.success("✅ No vulnerabilities found!")
    
    except Exception as e:
        st.error(f"Error loading scan details: {e}")

def show_alerts():
    """Display security alerts"""
    st.header("🚨 Security Alerts")
    
    try:
        alerts = load_active_alerts()
        
        if alerts.empty:
            st.success("✅ No active alerts!")
            return
        
        # Filter
        alert_type = st.multiselect(
            "Filter by type",
            alerts['alert_type'].unique(),
            default=alerts['alert_type'].unique()
        )
        
        filtered = alerts[alerts['alert_type'].isin(alert_type)]
        
        # Display alerts
        for _, alert in filtered.iterrows():
            severity_color = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(alert['severity'], '⚪')
            
            with st.expander(f"{severity_color} {alert['title']}", expanded=True):
                st.markdown(f"**Type:** {alert['alert_type']}")
                st.markdown(f"**Severity:** {alert['severity'].upper()}")
                st.markdown(f"**Time:** {alert['alert_timestamp']}")
                st.markdown(f"**Status:** {alert['status']}")
                st.markdown("---")
                st.markdown(alert['description'])
    
    except Exception as e:
        st.error(f"Error loading alerts: {e}")

def show_analytics():
    """Display analytics and trends"""
    st.header("📈 Analytics")
    
    try:
        df = load_latest_scans(200)
        
        if df.empty:
            st.info("No data available for analytics")
            return
        
        # Time range selector
        days = st.slider("Time range (days)", 7, 90, 30)
        cutoff = datetime.now() - timedelta(days=days)
        df['scan_timestamp'] = pd.to_datetime(df['scan_timestamp'])
        df = df[df['scan_timestamp'] >= cutoff]
        
        # Severity distribution
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Severity Distribution")
            severity_data = pd.DataFrame({
                'Severity': ['Critical', 'High', 'Medium', 'Low'],
                'Count': [
                    df['critical_count'].sum(),
                    df['high_count'].sum(),
                    df['medium_count'].sum(),
                    df['low_count'].sum()
                ]
            })
            fig = px.pie(severity_data, values='Count', names='Severity',
                        color='Severity',
                        color_discrete_map={
                            'Critical': '#ff4b4b',
                            'High': '#ffa500',
                            'Medium': '#ffeb3b',
                            'Low': '#4caf50'
                        })
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Risk Category Distribution")
            if 'risk_category' in df.columns:
                risk_counts = df['risk_category'].value_counts()
                fig = px.bar(x=risk_counts.index, y=risk_counts.values,
                           labels={'x': 'Risk Category', 'y': 'Count'},
                           color=risk_counts.index,
                           color_discrete_map={
                               'critical': '#ff4b4b',
                               'high': '#ffa500',
                               'medium': '#ffeb3b',
                               'low': '#4caf50'
                           })
                st.plotly_chart(fig, use_container_width=True)
        
        # Timeline
        st.subheader("Vulnerability Timeline")
        df_timeline = df.groupby(df['scan_timestamp'].dt.date).agg({
            'total_vulnerabilities': 'sum',
            'critical_count': 'sum',
            'high_count': 'sum'
        }).reset_index()
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=df_timeline['scan_timestamp'], 
                                y=df_timeline['critical_count'],
                                name='Critical', mode='lines+markers'))
        fig.add_trace(go.Scatter(x=df_timeline['scan_timestamp'], 
                                y=df_timeline['high_count'],
                                name='High', mode='lines+markers'))
        fig.update_layout(xaxis_title="Date", yaxis_title="Count", height=400)
        st.plotly_chart(fig, use_container_width=True)
        
    except Exception as e:
        st.error(f"Error loading analytics: {e}")

if __name__ == "__main__":
    main()