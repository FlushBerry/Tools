#!/bin/bash
# ============================================================================
#  s3-http-audit.sh — Détecte les buckets S3 accessibles en HTTP (non-HTTPS)
# ============================================================================

PROFILE="${1:-mfa}"
OUTPUT="s3-http-audit-$(date +%Y%m%d-%H%M%S).csv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  🔓 S3 HTTP Exposure Audit — Profile: $PROFILE${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# CSV header
echo "Bucket,Region,HTTP_Code,HTTPS_Code,SecureTransport_Policy,Verdict" > "$OUTPUT"

# 1. Liste tous les buckets
BUCKETS=$(aws s3api list-buckets --profile "$PROFILE" --query 'Buckets[].Name' --output text)

if [ -z "$BUCKETS" ]; then
  echo -e "${RED}❌ Aucun bucket trouvé ou erreur d'auth${NC}"
  exit 1
fi

TOTAL=$(echo "$BUCKETS" | wc -w)
echo -e "${CYAN}📦 $TOTAL buckets à analyser${NC}\n"

VULN_COUNT=0
SECURE_COUNT=0

for BUCKET in $BUCKETS; do
  # 2. Récupère la région
  REGION=$(aws s3api get-bucket-location --bucket "$BUCKET" --profile "$PROFILE" \
    --query 'LocationConstraint' --output text 2>/dev/null)
  [ "$REGION" == "None" ] || [ -z "$REGION" ] && REGION="us-east-1"

  # 3. Test HTTP & HTTPS
  HTTP_CODE=$(curl -sI -o /dev/null -m 5 -w "%{http_code}" \
    "http://${BUCKET}.s3.${REGION}.amazonaws.com/" 2>/dev/null)
  HTTPS_CODE=$(curl -sI -o /dev/null -m 5 -w "%{http_code}" \
    "https://${BUCKET}.s3.${REGION}.amazonaws.com/" 2>/dev/null)

  # 4. Check policy SecureTransport
  POLICY=$(aws s3api get-bucket-policy --bucket "$BUCKET" --profile "$PROFILE" \
    --query Policy --output text 2>/dev/null)

  if echo "$POLICY" | jq -e '.Statement[] | select(.Effect=="Deny") | select(.Condition.Bool."aws:SecureTransport"=="false")' &>/dev/null; then
    SECURE_TRANSPORT="ENFORCED"
  else
    SECURE_TRANSPORT="MISSING"
  fi

  # 5. Verdict
  if [ "$SECURE_TRANSPORT" == "MISSING" ] && [[ "$HTTP_CODE" =~ ^(200|301|307|403)$ ]]; then
    VERDICT="VULNERABLE"
    VULN_COUNT=$((VULN_COUNT+1))
    echo -e "${RED}${BOLD}🚨 [$VERDICT]${NC} ${BOLD}$BUCKET${NC} (${REGION})"
    echo -e "    HTTP=$HTTP_CODE | HTTPS=$HTTPS_CODE | Policy=${RED}$SECURE_TRANSPORT${NC}"
  else
    VERDICT="SECURE"
    SECURE_COUNT=$((SECURE_COUNT+1))
    echo -e "${GREEN}✅ [$VERDICT]${NC} $BUCKET (${REGION}) — Policy=$SECURE_TRANSPORT"
  fi

  echo "$BUCKET,$REGION,$HTTP_CODE,$HTTPS_CODE,$SECURE_TRANSPORT,$VERDICT" >> "$OUTPUT"
done

# 6. Résumé
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}📊 RÉSUMÉ${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "   Total buckets   : $TOTAL"
echo -e "   ${RED}🚨 Vulnérables  : $VULN_COUNT${NC}"
echo -e "   ${GREEN}✅ Sécurisés    : $SECURE_COUNT${NC}"
echo ""
echo -e "${YELLOW}📄 Rapport CSV : $OUTPUT${NC}"

# 7. Affiche les vulnérables en fin
if [ $VULN_COUNT -gt 0 ]; then
  echo ""
  echo -e "${RED}${BOLD}━━━ BUCKETS VULNÉRABLES (HTTP autorisé) ━━━${NC}"
  grep "VULNERABLE" "$OUTPUT" | awk -F',' '{printf "  • %-50s [%s] HTTP=%s HTTPS=%s\n", $1, $2, $3, $4}'
fi
