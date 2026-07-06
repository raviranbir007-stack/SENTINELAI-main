#!/bin/bash

# SentinelAI IDS/IPS Configuration Helper
# Quick commands to manage your improved security system

echo "╔════════════════════════════════════════════════════════╗"
echo "║     SentinelAI IDS/IPS Management Console             ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

show_help() {
    echo "Available Commands:"
    echo ""
    echo "1. View Current Firewall Rules"
    echo "   sudo iptables -L -n | grep DROP    # IPv4"
    echo "   sudo ip6tables -L -n | grep DROP   # IPv6"
    echo ""
    echo "2. Clear All Blocked IPs"
    echo "   sudo iptables -F                   # IPv4"
    echo "   sudo ip6tables -F                  # IPv6"
    echo ""
    echo "3. Unblock Specific IP"
    echo "   sudo iptables -D INPUT -s <IP> -j DROP"
    echo "   sudo ip6tables -D INPUT -s <IP> -j DROP"
    echo ""
    echo "4. View System Logs"
    echo "   tail -f logs/sentinel_client.log | grep -E 'INTRUSION|BLOCKED'"
    echo ""
    echo "5. Check Whitelisted IPs"
    echo "   cat << EOF | python3"
    echo "   from client.scanner.intrusion_detector import IntrusionDetector"
    echo "   ids = IntrusionDetector()"
    echo "   test_ips = ['127.0.0.1', '142.250.70.42', '203.0.113.42']"
    echo "   for ip in test_ips:"
    echo "       print(f'{ip}: {\"Whitelisted\" if ids._is_whitelisted_ip(ip) else \"Not whitelisted\"}')"
    echo "   EOF"
    echo ""
    echo "6. Monitor Real-Time Attacks"
    echo "   watch -n 1 'tail -20 logs/sentinel_client.log | grep -E \"ALERT|INTRUSION\"'"
    echo ""
    echo "7. Test IDS Detection"
    echo "   # Safe test - won't trigger (localhost whitelisted)"
    echo "   for i in {1..100}; do curl -s http://localhost:5000/api/health > /dev/null & done"
    echo ""
    echo "8. Statistics"
    echo "   echo 'Blocked IPs (IPv4):' && sudo iptables -L INPUT -n | grep DROP | wc -l"
    echo "   echo 'Blocked IPs (IPv6):' && sudo ip6tables -L INPUT -n | grep DROP | wc -l"
    echo ""
}

case "$1" in
    "rules"|"list")
        echo "📋 Current Firewall Rules:"
        echo ""
        echo "IPv4 Rules:"
        sudo iptables -L INPUT -n | grep DROP | head -10
        echo ""
        echo "IPv6 Rules:"
        sudo ip6tables -L INPUT -n | grep DROP | head -10
        ;;
    
    "clear"|"flush")
        echo "⚠️  Clearing all firewall rules..."
        sudo iptables -F
        sudo ip6tables -F
        echo "✅ All rules cleared"
        ;;
    
    "unblock")
        if [ -z "$2" ]; then
            echo "Usage: $0 unblock <IP_ADDRESS>"
            exit 1
        fi
        echo "🔓 Unblocking $2..."
        sudo iptables -D INPUT -s $2 -j DROP 2>/dev/null || echo "No IPv4 rule found"
        sudo ip6tables -D INPUT -s $2 -j DROP 2>/dev/null || echo "No IPv6 rule found"
        echo "✅ Unblock attempted for $2"
        ;;
    
    "stats"|"status")
        echo "📊 IDS/IPS Statistics:"
        echo ""
        ipv4_count=$(sudo iptables -L INPUT -n | grep DROP | wc -l)
        ipv6_count=$(sudo ip6tables -L INPUT -n | grep DROP | wc -l)
        echo "Blocked IPs (IPv4): $ipv4_count"
        echo "Blocked IPs (IPv6): $ipv6_count"
        echo "Total Blocked: $((ipv4_count + ipv6_count))"
        echo ""
        if [ -f "logs/sentinel_client.log" ]; then
            echo "Recent Alerts:"
            tail -50 logs/sentinel_client.log | grep -E "INTRUSION|BLOCKED" | tail -5
        fi
        ;;
    
    "monitor"|"watch")
        echo "👁️  Monitoring attacks in real-time (Ctrl+C to stop)..."
        echo ""
        tail -f logs/sentinel_client.log 2>/dev/null | grep --line-buffered -E "INTRUSION|BLOCKED|ALERT"
        ;;
    
    "test")
        echo "🧪 Testing IDS/IPS System..."
        echo ""
        echo "Testing whitelisted IP (should NOT block):"
        for i in {1..10}; do
            curl -s http://localhost:5000/api/health > /dev/null 2>&1 &
        done
        wait
        echo "✅ Test completed - check logs for any false positives"
        ;;
    
    "whitelist")
        echo "✅ Checking Whitelisted IP Ranges:"
        echo ""
        echo "Localhost: 127.0.0.1, ::1"
        echo "Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
        echo "Google: 142.250.0.0/15, 34.64.0.0/10"
        echo "Cloudflare: 104.16.0.0/13, 172.64.0.0/13"
        echo "Fastly CDN: 151.101.0.0/16"
        ;;
    
    *)
        show_help
        ;;
esac

echo ""
