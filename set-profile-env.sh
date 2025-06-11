#!/bin/bash
# =============================================================================
# SCRIPT PARA CONFIGURAR VARIABLES DE ENTORNO POR PERFIL
# =============================================================================

# Colores para output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Función para mostrar banner
show_banner() {
    echo -e "${BLUE}"
    echo "=============================================================================="
    echo "   _____ ___ ____ ____   ____ _    _   _ ____       _    ____ ___ "
    echo "  |  ___|_ _/ ___|  _ \ / ___| |  | | | | __ )     / \  |  _ \_ _|"
    echo "  | |_   | | |  _| |_) | |   | |  | | | |  _ \    / _ \ | |_) | | "
    echo "  |  _|  | | |_| |  _ <| |___| |__| |_| | |_) |  / ___ \|  __/| | "
    echo "  |_|   |___\____|_| \_\\____|_____\___/|____/  /_/   \_\_|  |___|"
    echo ""
    echo "                    RATE LIMITING SETUP v2.0"
    echo "=============================================================================="
    echo -e "${NC}"
}

# Función para configurar desarrollo
setup_dev() {
    echo -e "${BLUE}🔧 Configurando variables para DESARROLLO...${NC}"

    export SPRING_PROFILES_ACTIVE=dev
    export RATE_LIMIT_ENABLED=true
    export RATE_LIMIT_MAX_ATTEMPTS_PER_IP=20
    export RATE_LIMIT_MAX_ATTEMPTS_PER_USER=10
    export RATE_LIMIT_WINDOW_MINUTES=30
    export RATE_LIMIT_BLOCK_DURATION_MINUTES=15
    export RATE_LIMIT_PROGRESSIVE_BLOCK=false
    export RATE_LIMIT_WHITELIST_IPS="127.0.0.1,::1,192.168.1.0/24"

    echo -e "${GREEN}✅ Variables de desarrollo configuradas${NC}"
    echo -e "   📊 Rate Limiting: PERMISIVO (20 intentos/IP)${NC}"
}

# Función para configurar testing
setup_test() {
    echo -e "${BLUE}🔧 Configurando variables para TESTING...${NC}"

    export SPRING_PROFILES_ACTIVE=test
    export RATE_LIMIT_ENABLED=false

    echo -e "${GREEN}✅ Variables de testing configuradas${NC}"
    echo -e "   📊 Rate Limiting: DESHABILITADO${NC}"
}

# Función para configurar producción
setup_prod() {
    echo -e "${BLUE}🔧 Configurando variables para PRODUCCIÓN...${NC}"

    export SPRING_PROFILES_ACTIVE=prod
    export RATE_LIMIT_ENABLED=true
    export RATE_LIMIT_MAX_ATTEMPTS_PER_IP=5
    export RATE_LIMIT_MAX_ATTEMPTS_PER_USER=3
    export RATE_LIMIT_WINDOW_MINUTES=10
    export RATE_LIMIT_BLOCK_DURATION_MINUTES=60
    export RATE_LIMIT_PROGRESSIVE_BLOCK=true
    export RATE_LIMIT_WHITELIST_IPS="127.0.0.1,::1"

    # Login muy restrictivo
    export RATE_LIMIT_LOGIN_MAX_ATTEMPTS_PER_IP=3
    export RATE_LIMIT_LOGIN_MAX_ATTEMPTS_PER_USER=3
    export RATE_LIMIT_LOGIN_BLOCK_DURATION_MINUTES=120

    echo -e "${GREEN}✅ Variables de producción configuradas${NC}"
    echo -e "   📊 Rate Limiting: ESTRICTO (5 intentos/IP)${NC}"
    echo -e "${YELLOW}⚠️  Recuerda configurar las variables sensibles:${NC}"
    echo -e "   - DATABASE_URL, DATABASE_USERNAME, DATABASE_PASSWORD${NC}"
    echo -e "   - JWT_SECRET, MAIL_USERNAME, MAIL_PASSWORD${NC}"
}

# Función para mostrar variables actuales
show_current() {
    echo -e "${BLUE}📋 Variables de entorno actuales:${NC}"
    echo -e "   SPRING_PROFILES_ACTIVE: ${SPRING_PROFILES_ACTIVE:-'No definido'}"
    echo -e "   RATE_LIMIT_ENABLED: ${RATE_LIMIT_ENABLED:-'No definido'}"
    echo -e "   RATE_LIMIT_MAX_ATTEMPTS_PER_IP: ${RATE_LIMIT_MAX_ATTEMPTS_PER_IP:-'No definido'}"
    echo -e "   RATE_LIMIT_MAX_ATTEMPTS_PER_USER: ${RATE_LIMIT_MAX_ATTEMPTS_PER_USER:-'No definido'}"
}

# Función principal
main() {
    local profile=${1:-dev}

    case $profile in
        dev|development)
            setup_dev
            ;;
        test|testing)
            setup_test
            ;;
        prod|production)
            setup_prod
            ;;
        show)
            show_current
            ;;
        help|--help|-h)
            echo "Uso: source $0 [PERFIL]"
            echo ""
            echo "PERFILES:"
            echo "  dev   - Desarrollo (Rate limiting permisivo)"
            echo "  test  - Testing (Rate limiting deshabilitado)"
            echo "  prod  - Producción (Rate limiting estricto)"
            echo "  show  - Mostrar variables actuales"
            echo ""
            echo "EJEMPLOS:"
            echo "  source $0 dev    # Configurar para desarrollo"
            echo "  source $0 prod   # Configurar para producción"
            echo "  source $0 show   # Ver variables actuales"
            echo ""
            echo "NOTA: Usar 'source' para que las variables se exporten al shell actual"
            ;;
        *)
            echo -e "${RED}❌ Perfil no válido: $profile${NC}"
            echo -e "${YELLOW}Perfiles disponibles: dev, test, prod${NC}"
            echo -e "${YELLOW}Usa: source $0 help para más información${NC}"
            exit 1
            ;;
    esac
}

# Ejecutar función principal
main "$@"