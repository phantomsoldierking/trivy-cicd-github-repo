#!/bin/bash

# Helper utility functions for the security pipeline

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function: Check service health
check_service_health() {
    local service=$1
    echo -e "${BLUE}Checking $service...${NC}"
    
    if docker-compose ps $service | grep -q "Up"; then
        echo -e "${GREEN}✓ $service is running${NC}"
        return 0
    else
        echo -e "${RED}✗ $service is not running${NC}"
        return 1
    fi
}

# Function: Check all services
check_all_services() {
    echo -e "${YELLOW}Service Health Check${NC}"
    echo "========================"
    
    local all_healthy=true
    
    for service in postgres localstack mlflow scanner ml_service dashboard; do
        if ! check_service_health $service; then
            all_healthy=false
        fi
    done
    
    echo ""
    if [ "$all_healthy" = true ]; then
        echo -e "${GREEN}All services are healthy!${NC}"
    else
        echo -e "${RED}Some services are down. Run: docker-compose up -d${NC}"
    fi
}

# Function: Clean database
clean_database() {
    echo -e "${YELLOW}WARNING: This will delete all data!${NC}"
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "$confirm" = "yes" ]; then
        echo -e "${BLUE}Cleaning database...${NC}"
        docker-compose exec postgres psql -U security_user -d security_db -c "
        TRUNCATE TABLE security_alerts CASCADE;
        TRUNCATE TABLE ml_predictions CASCADE;
        TRUNCATE TABLE ml_features CASCADE;
        TRUNCATE TABLE vulnerabilities CASCADE;
        TRUNCATE TABLE scan_results CASCADE;
        TRUNCATE TABLE model_metrics CASCADE;
        "
        echo -e "${GREEN}✓ Database cleaned${NC}"
    else
        echo "Cancelled"
    fi
}

# Function: Export data
export_data() {
    local output_dir="./exports/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"
    
    echo -e "${BLUE}Exporting data to $output_dir${NC}"
    
    # Export scan results
    docker-compose exec -T postgres psql -U security_user -d security_db -c \
        "COPY (SELECT * FROM scan_results) TO STDOUT WITH CSV HEADER" > "$output_dir/scan_results.csv"
    
    # Export vulnerabilities
    docker-compose exec -T postgres psql -U security_user -d security_db -c \
        "COPY (SELECT * FROM vulnerabilities) TO STDOUT WITH CSV HEADER" > "$output_dir/vulnerabilities.csv"
    
    # Export predictions
    docker-compose exec -T postgres psql -U security_user -d security_db -c \
        "COPY (SELECT * FROM ml_predictions) TO STDOUT WITH CSV HEADER" > "$output_dir/predictions.csv"
    
    # Export alerts
    docker-compose exec -T postgres psql -U security_user -d security_db -c \
        "COPY (SELECT * FROM security_alerts) TO STDOUT WITH CSV HEADER" > "$output_dir/alerts.csv"
    
    echo -e "${GREEN}✓ Data exported to $output_dir${NC}"
    ls -lh "$output_dir"
}

# Function: Show statistics
show_statistics() {
    echo -e "${YELLOW}Database Statistics${NC}"
    echo "========================"
    
    docker-compose exec postgres psql -U security_user -d security_db << 'EOF'
\echo '=== Scan Statistics ==='
SELECT 
    COUNT(*) as total_scans,
    COUNT(DISTINCT image_name) as unique_images,
    SUM(total_vulnerabilities) as total_vulns,
    AVG(total_vulnerabilities)::NUMERIC(10,2) as avg_vulns_per_scan,
    SUM(critical_count) as total_critical,
    SUM(high_count) as total_high
FROM scan_results;

\echo ''
\echo '=== ML Statistics ==='
SELECT 
    COUNT(*) as total_predictions,
    SUM(CASE WHEN is_anomaly THEN 1 ELSE 0 END) as anomalies_detected,
    AVG(risk_score)::NUMERIC(10,2) as avg_risk_score,
    COUNT(CASE WHEN risk_score >= 80 THEN 1 END) as critical_risk_scans
FROM ml_predictions;

\echo ''
\echo '=== Alert Statistics ==='
SELECT 
    COUNT(*) as total_alerts,
    SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_alerts,
    COUNT(DISTINCT alert_type) as alert_types
FROM security_alerts;

\echo ''
\echo '=== Recent Activity ==='
SELECT 
    DATE(scan_timestamp) as date,
    COUNT(*) as scans
FROM scan_results
WHERE scan_timestamp > CURRENT_DATE - INTERVAL '7 days'
GROUP BY DATE(scan_timestamp)
ORDER BY date DESC;
EOF
}

# Function: Backup database
backup_database() {
    local backup_dir="./backups"
    mkdir -p "$backup_dir"
    
    local backup_file="$backup_dir/security_db_$(date +%Y%m%d_%H%M%S).sql"
    
    echo -e "${BLUE}Creating database backup...${NC}"
    docker-compose exec -T postgres pg_dump -U security_user security_db > "$backup_file"
    
    # Compress backup
    gzip "$backup_file"
    
    echo -e "${GREEN}✓ Backup created: ${backup_file}.gz${NC}"
    ls -lh "${backup_file}.gz"
}

# Function: Restore database
restore_database() {
    local backup_file=$1
    
    if [ -z "$backup_file" ]; then
        echo -e "${RED}Usage: restore_database <backup_file>${NC}"
        return 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        echo -e "${RED}Backup file not found: $backup_file${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}WARNING: This will replace all existing data!${NC}"
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "$confirm" = "yes" ]; then
        echo -e "${BLUE}Restoring database...${NC}"
        
        # Decompress if needed
        if [[ $backup_file == *.gz ]]; then
            gunzip -c "$backup_file" | docker-compose exec -T postgres psql -U security_user security_db
        else
            cat "$backup_file" | docker-compose exec -T postgres psql -U security_user security_db
        fi
        
        echo -e "${GREEN}✓ Database restored${NC}"
    else
        echo "Cancelled"
    fi
}

# Function: View logs
view_logs() {
    local service=$1
    local lines=${2:-100}
    
    if [ -z "$service" ]; then
        echo "Available services: postgres, localstack, mlflow, scanner, ml_service, dashboard"
        read -p "Enter service name: " service
    fi
    
    echo -e "${BLUE}Showing last $lines lines of $service logs:${NC}"
    docker-compose logs --tail=$lines -f $service
}

# Function: Run database migrations
run_migrations() {
    echo -e "${BLUE}Running database migrations...${NC}"
    
    for migration in database/migrations/*.sql; do
        if [ -f "$migration" ]; then
            echo -e "${YELLOW}Applying: $(basename $migration)${NC}"
            docker-compose exec -T postgres psql -U security_user -d security_db -f - < "$migration"
            echo -e "${GREEN}✓ Applied: $(basename $migration)${NC}"
        fi
    done
    
    echo -e "${GREEN}✓ All migrations applied${NC}"
}

# Function: Quick scan
quick_scan() {
    local image=$1
    
    if [ -z "$image" ]; then
        echo "Usage: quick_scan <image_name[:tag]>"
        return 1
    fi
    
    # Parse image and tag
    if [[ $image == *:* ]]; then
        IFS=':' read -r img_name img_tag <<< "$image"
    else
        img_name=$image
        img_tag="latest"
    fi
    
    echo -e "${BLUE}Quick scanning: $img_name:$img_tag${NC}"
    
    # Pull if needed
    if ! docker images | grep -q "$img_name.*$img_tag"; then
        docker pull "$img_name:$img_tag"
    fi
    
    # Run pipeline
    ./scripts/run_pipeline.sh "$img_name" "$img_tag"
}

# Function: Generate report
generate_report() {
    local output_file="security_report_$(date +%Y%m%d_%H%M%S).html"
    
    echo -e "${BLUE}Generating HTML report...${NC}"
    
    docker-compose exec -T postgres psql -U security_user -d security_db << 'EOF' > /tmp/report_data.txt
\echo '=== Security Report ==='
\echo 'Generated: ' 
SELECT CURRENT_TIMESTAMP;
\echo ''

\echo '=== Executive Summary ==='
SELECT 
    COUNT(DISTINCT image_name) as total_images,
    COUNT(*) as total_scans,
    SUM(total_vulnerabilities) as total_vulnerabilities,
    SUM(critical_count) as critical_vulnerabilities,
    AVG(risk_score)::NUMERIC(10,2) as avg_risk_score
FROM scan_results sr
LEFT JOIN ml_predictions mp ON sr.scan_id = mp.scan_id
WHERE sr.scan_timestamp > CURRENT_DATE - INTERVAL '30 days';

\echo ''
\echo '=== Top 10 Riskiest Images ==='
SELECT 
    sr.image_name || ':' || sr.image_tag as image,
    sr.total_vulnerabilities as vulns,
    sr.critical_count as critical,
    mp.risk_score::NUMERIC(10,1) as risk
FROM scan_results sr
LEFT JOIN ml_predictions mp ON sr.scan_id = mp.scan_id
WHERE sr.scan_timestamp > CURRENT_DATE - INTERVAL '30 days'
ORDER BY mp.risk_score DESC NULLS LAST
LIMIT 10;

\echo ''
\echo '=== Active Critical Alerts ==='
SELECT 
    alert_type,
    title,
    severity
FROM security_alerts
WHERE status = 'open' AND severity IN ('critical', 'high')
ORDER BY alert_timestamp DESC
LIMIT 10;
EOF
    
    # Convert to basic HTML
    cat > "$output_file" << 'HTML'
<!DOCTYPE html>
<html>
<head>
    <title>Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; }
    </style>
</head>
<body>
    <h1>Container Security Report</h1>
    <pre>
HTML
    
    cat /tmp/report_data.txt >> "$output_file"
    
    cat >> "$output_file" << 'HTML'
    </pre>
</body>
</html>
HTML
    
    echo -e "${GREEN}✓ Report generated: $output_file${NC}"
    echo "Open with: xdg-open $output_file"
}

# Main menu
show_menu() {
    echo ""
    echo -e "${CYAN}Container Security Pipeline - Helper Tools${NC}"
    echo "==========================================="
    echo "1. Check service health"
    echo "2. Show statistics"
    echo "3. Export data"
    echo "4. Backup database"
    echo "5. Restore database"
    echo "6. View logs"
    echo "7. Clean database"
    echo "8. Run migrations"
    echo "9. Quick scan"
    echo "10. Generate report"
    echo "0. Exit"
    echo ""
    read -p "Select option: " choice
    
    case $choice in
        1) check_all_services ;;
        2) show_statistics ;;
        3) export_data ;;
        4) backup_database ;;
        5) 
            read -p "Enter backup file path: " backup_file
            restore_database "$backup_file"
            ;;
        6) 
            read -p "Enter service name: " service
            view_logs "$service"
            ;;
        7) clean_database ;;
        8) run_migrations ;;
        9) 
            read -p "Enter image name[:tag]: " image
            quick_scan "$image"
            ;;
        10) generate_report ;;
        0) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    show_menu
}

# If script is run directly, show menu
if [ "${BASH_SOURCE[0]}" -ef "$0" ]; then
    show_menu
fi