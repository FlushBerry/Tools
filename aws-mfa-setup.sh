#!/bin/bash
#
# ============================================================================
#  AWS MFA Session Manager — Setup complet pour CloudFox / Prowler / ScoutSuite
# ============================================================================
#
#  Automatise :
#   1. Vérification creds long-terme (AKIA)
#   2. Détection auto du device MFA
#   3. Génération session temporaire MFA (12h)
#   4. Écriture du profil 'mfa' dans ~/.aws/credentials
#   5. Validation contexte MFA
#   6. Affichage des commandes prêtes pour CloudFox, Prowler, ScoutSuite
#
#  Usage      : ./aws-mfa-setup.sh
#  Pré-requis : aws-cli v2, jq
#  Optionnel  : cloudfox, prowler, scoutsuite (installés séparément) 
#  -> go install github.com/BishopFox/cloudfox@latest
#  -> pip install prowler
#  -> pip install scoutsuite
#
# ============================================================================

set -e

# ----------------------------------------------------------------------------
# COULEURS
# ----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ----------------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------------
SOURCE_PROFILE="default"
TARGET_PROFILE="mfa"
REGION="eu-west-1"
DURATION=43200             # 12h
OUTPUT_DIR="./audit-$(date +%Y%m%d-%H%M%S)"

# ============================================================================
# ÉTAPE 0 — Pré-flight
# ============================================================================
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  🔐 AWS MFA Session Setup + Multi-Tool Audit${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

for cmd in aws jq; do
  if ! command -v $cmd &> /dev/null; then
    echo -e "${RED}❌ '$cmd' n'est pas installé${NC}"
    echo "   Installe : brew install $cmd  (ou apt install $cmd)"
    exit 1
  fi
done
echo -e "${GREEN}✅ Pré-requis OK (aws-cli, jq)${NC}"

# Check optionnel des outils d'audit
CLOUDFOX_OK=false; PROWLER_OK=false; SCOUT_OK=false
command -v cloudfox   &>/dev/null && CLOUDFOX_OK=true
command -v prowler    &>/dev/null && PROWLER_OK=true
command -v scout      &>/dev/null && SCOUT_OK=true

echo ""
echo -e "${CYAN}🛠️  Outils d'audit détectés :${NC}"
$CLOUDFOX_OK && echo -e "   ${GREEN}✅ cloudfox${NC}"   || echo -e "   ${YELLOW}⚠️  cloudfox absent${NC}   → go install github.com/BishopFox/cloudfox@latest"
$PROWLER_OK  && echo -e "   ${GREEN}✅ prowler${NC}"    || echo -e "   ${YELLOW}⚠️  prowler absent${NC}    → pip install prowler"
$SCOUT_OK    && echo -e "   ${GREEN}✅ scoutsuite${NC}" || echo -e "   ${YELLOW}⚠️  scoutsuite absent${NC} → pip install scoutsuite"

# ============================================================================
# ÉTAPE 1 — Creds long-terme
# ============================================================================
echo ""
echo -e "${CYAN}━━━ Étape 1 : Creds long-terme ━━━${NC}"
echo -e "${YELLOW}ℹ️  Profil source : '$SOURCE_PROFILE' (doit contenir des AKIA...)${NC}"

IDENTITY=$(aws sts get-caller-identity --profile "$SOURCE_PROFILE" --output json 2>&1) || {
  echo -e "${RED}❌ Auth échouée avec '$SOURCE_PROFILE'${NC}"
  echo "$IDENTITY"
  exit 1
}

USER_ARN=$(echo "$IDENTITY" | jq -r '.Arn')
USER_ID=$(echo "$IDENTITY" | jq -r '.UserId')
ACCOUNT_ID=$(echo "$IDENTITY" | jq -r '.Account')

echo -e "${GREEN}✅ Authentifié${NC}"
echo "   ARN     : $USER_ARN"
echo "   UserId  : $USER_ID  (AIDA = user IAM, normal)"
echo "   Account : $ACCOUNT_ID"

# ============================================================================
# ÉTAPE 2 — Device MFA
# ============================================================================
echo ""
echo -e "${CYAN}━━━ Étape 2 : Device MFA ━━━${NC}"
echo -e "${YELLOW}ℹ️  list-mfa-devices liste les MFA attachés au user${NC}"

MFA_DEVICES=$(aws iam list-mfa-devices --profile "$SOURCE_PROFILE" --output json 2>&1) || {
  echo -e "${RED}❌ Impossible de lister les MFA${NC}"
  echo "$MFA_DEVICES"
  exit 1
}

MFA_COUNT=$(echo "$MFA_DEVICES" | jq '.MFADevices | length')

if [ "$MFA_COUNT" -eq 0 ]; then
  echo -e "${RED}❌ Aucun device MFA enregistré${NC}"
  exit 1
fi

if [ "$MFA_COUNT" -gt 1 ]; then
  echo "Plusieurs devices :"
  echo "$MFA_DEVICES" | jq -r '.MFADevices[] | "  - \(.SerialNumber)"'
  read -p "Colle l'ARN : " MFA_ARN
else
  MFA_ARN=$(echo "$MFA_DEVICES" | jq -r '.MFADevices[0].SerialNumber')
fi

echo -e "${GREEN}✅ Device MFA : $MFA_ARN${NC}"

# ============================================================================
# ÉTAPE 3 — Code TOTP
# ============================================================================
echo ""
echo -e "${CYAN}━━━ Étape 3 : Code MFA ━━━${NC}"
echo -e "${YELLOW}ℹ️  Ouvre Authy/Google Auth/YubiKey${NC}"
echo -e "${YELLOW}⚠️  Code FRAIS (>15s restantes)${NC}"

read -p "Code MFA (6 chiffres) : " MFA_CODE

if ! [[ "$MFA_CODE" =~ ^[0-9]{6}$ ]]; then
  echo -e "${RED}❌ Doit faire 6 chiffres${NC}"
  exit 1
fi

# ============================================================================
# ÉTAPE 4 — get-session-token
# ============================================================================
echo ""
echo -e "${CYAN}━━━ Étape 4 : Génération session MFA ━━━${NC}"
echo -e "${YELLOW}ℹ️  Échange (AKIA + code MFA) → ASIA temporaire avec MFA flag${NC}"

CREDS=$(aws sts get-session-token \
  --profile "$SOURCE_PROFILE" \
  --serial-number "$MFA_ARN" \
  --token-code "$MFA_CODE" \
  --duration-seconds "$DURATION" \
  --output json 2>&1) || {
  echo -e "${RED}❌ Échec get-session-token${NC}"
  echo "$CREDS"
  echo ""
  echo "Causes : code expiré / horloge désync / mauvais SerialNumber"
  exit 1
}

AKI=$(echo "$CREDS" | jq -r '.Credentials.AccessKeyId')
SAK=$(echo "$CREDS" | jq -r '.Credentials.SecretAccessKey')
TOK=$(echo "$CREDS" | jq -r '.Credentials.SessionToken')
EXP=$(echo "$CREDS" | jq -r '.Credentials.Expiration')

echo -e "${GREEN}✅ Session générée${NC}"
echo "   AccessKey : ${AKI:0:10}...  (ASIA = temporaire ✅)"
echo "   Expire    : $EXP"

# ============================================================================
# ÉTAPE 5 — Écriture profil
# ============================================================================
echo ""
echo -e "${CYAN}━━━ Étape 5 : Écriture profil '$TARGET_PROFILE' ━━━${NC}"

aws configure set aws_access_key_id     "$AKI" --profile "$TARGET_PROFILE"
aws configure set aws_secret_access_key "$SAK" --profile "$TARGET_PROFILE"
aws configure set aws_session_token     "$TOK" --profile "$TARGET_PROFILE"
aws configure set region                "$REGION" --profile "$TARGET_PROFILE"
aws configure set output                "json" --profile "$TARGET_PROFILE"

chmod 600 ~/.aws/credentials 2>/dev/null || true

echo -e "${GREEN}✅ Profil '$TARGET_PROFILE' écrit${NC}"

# ============================================================================
# ÉTAPE 6 — Validation MFA
# ============================================================================
echo ""
echo -e "${CYAN}━━━ Étape 6 : Validation contexte MFA ━━━${NC}"

aws sts get-caller-identity --profile "$TARGET_PROFILE" --output json | jq .

if aws iam get-account-summary --profile "$TARGET_PROFILE" > /dev/null 2>&1; then
  echo -e "${GREEN}✅ Contexte MFA propagé (get-account-summary OK)${NC}"
else
  echo -e "${YELLOW}⚠️  get-account-summary échoue (droits ou MFA absent)${NC}"
fi

# ============================================================================
# ÉTAPE 7 — Préparation env + dossier output
# ============================================================================
echo ""
echo -e "${CYAN}━━━ Étape 7 : Préparation audit ━━━${NC}"
mkdir -p "$OUTPUT_DIR"/{cloudfox,prowler,scoutsuite}
echo -e "${GREEN}✅ Dossier créé : $OUTPUT_DIR${NC}"

# ============================================================================
# RÉCAP FINAL — Commandes prêtes à copier
# ============================================================================
cat <<EOF

${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${GREEN}  🎉 Session MFA active — Prête pour l'audit${NC}
${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

${CYAN}⏰ Session valide jusqu'à : ${GREEN}$EXP${NC}
${CYAN}📁 Dossier d'audit         : ${GREEN}$OUTPUT_DIR${NC}

${CYAN}📌 Activer le profil dans ton shell :${NC}
   ${YELLOW}export AWS_PROFILE=$TARGET_PROFILE${NC}
   ${YELLOW}export AWS_REGION=$REGION${NC}

${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${MAGENTA}🦊 CLOUDFOX — Énumération offensive (fast, focus pentest)${NC}
${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

   # Sanity check
   ${YELLOW}cloudfox aws -p $TARGET_PROFILE whoami${NC}

   # Scan complet (tous modules)
   ${YELLOW}cloudfox aws -p $TARGET_PROFILE all-checks \\
     --outdir $OUTPUT_DIR/cloudfox${NC}

   # Modules ciblés utiles en pentest
   ${YELLOW}cloudfox aws -p $TARGET_PROFILE inventory${NC}        # vue d'ensemble
   ${YELLOW}cloudfox aws -p $TARGET_PROFILE permissions${NC}      # qui peut quoi
   ${YELLOW}cloudfox aws -p $TARGET_PROFILE iam-simulator${NC}    # privesc paths
   ${YELLOW}cloudfox aws -p $TARGET_PROFILE secrets${NC}          # secrets exposés
   ${YELLOW}cloudfox aws -p $TARGET_PROFILE buckets${NC}          # S3 publics
   ${YELLOW}cloudfox aws -p $TARGET_PROFILE endpoints${NC}        # URLs accessibles
   ${YELLOW}cloudfox aws -p $TARGET_PROFILE route53${NC}          # DNS / sous-domaines
   ${YELLOW}cloudfox aws -p $TARGET_PROFILE pmapper${NC}          # graph privesc

${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${MAGENTA}🛡️  PROWLER — Audit compliance (CIS, NIST, PCI, HIPAA, ISO)${NC}
${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

   # Scan complet (long mais exhaustif)
   ${YELLOW}prowler aws \\
     --profile $TARGET_PROFILE \\
     --output-directory $OUTPUT_DIR/prowler \\
     --output-formats html json-asff csv${NC}

   # Régions spécifiques (plus rapide)
   ${YELLOW}prowler aws -p $TARGET_PROFILE \\
     -f $REGION us-east-1 \\
     -o $OUTPUT_DIR/prowler${NC}

   # Compliance CIS uniquement
   ${YELLOW}prowler aws -p $TARGET_PROFILE \\
     --compliance cis_2.0_aws \\
     -o $OUTPUT_DIR/prowler${NC}

   # Sévérité critique + haute uniquement
   ${YELLOW}prowler aws -p $TARGET_PROFILE \\
     --severity critical high \\
     -o $OUTPUT_DIR/prowler${NC}

   # Services ciblés (rapide pour pentest)
   ${YELLOW}prowler aws -p $TARGET_PROFILE \\
     --services iam s3 ec2 rds lambda \\
     -o $OUTPUT_DIR/prowler${NC}

   # Checks spécifiques privesc / exposition
   ${YELLOW}prowler aws -p $TARGET_PROFILE \\
     --checks iam_user_mfa_enabled_console_access \\
              s3_bucket_public_access \\
              ec2_instance_public_ip \\
              iam_policy_allows_privilege_escalation \\
     -o $OUTPUT_DIR/prowler${NC}

   # Liste tous les checks dispo
   ${YELLOW}prowler aws --list-checks${NC}

${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${MAGENTA}🔍 SCOUTSUITE — Rapport HTML interactif global${NC}
${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

   # Scan AWS complet
   ${YELLOW}scout aws \\
     --profile $TARGET_PROFILE \\
     --report-dir $OUTPUT_DIR/scoutsuite${NC}

   # Régions ciblées (plus rapide)
   ${YELLOW}scout aws -p $TARGET_PROFILE \\
     --regions $REGION us-east-1 \\
     --report-dir $OUTPUT_DIR/scoutsuite${NC}

   # Services ciblés
   ${YELLOW}scout aws -p $TARGET_PROFILE \\
     --services iam s3 ec2 \\
     --report-dir $OUTPUT_DIR/scoutsuite${NC}

   # Sans tenter d'ouvrir le navigateur
   ${YELLOW}scout aws -p $TARGET_PROFILE \\
     --report-dir $OUTPUT_DIR/scoutsuite \\
     --no-browser${NC}

   # Ouvrir le rapport ensuite
   ${YELLOW}open $OUTPUT_DIR/scoutsuite/scoutsuite-report/*.html${NC}

${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${MAGENTA}🚀 PIPELINE COMPLET — Tout lancer en parallèle${NC}
${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

   ${YELLOW}export AWS_PROFILE=$TARGET_PROFILE${NC}

   ${YELLOW}(cloudfox aws all-checks --outdir $OUTPUT_DIR/cloudfox > $OUTPUT_DIR/cloudfox.log 2>&1) &${NC}
   ${YELLOW}(prowler aws -o $OUTPUT_DIR/prowler --severity critical high > $OUTPUT_DIR/prowler.log 2>&1) &${NC}
   ${YELLOW}(scout aws --report-dir $OUTPUT_DIR/scoutsuite --no-browser > $OUTPUT_DIR/scout.log 2>&1) &${NC}
   ${YELLOW}wait${NC}
   ${YELLOW}echo "✅ Tous les scans terminés → $OUTPUT_DIR"${NC}

${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${CYAN}🔁 Pour renouveler la session MFA : relance ce script${NC}
${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

EOF
