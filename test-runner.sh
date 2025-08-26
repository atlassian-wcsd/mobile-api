#!/bin/bash

# Comprehensive test runner for the Signature Application
# This script runs all tests for both frontend and backend components

set -e  # Exit on any error

echo "🧪 Starting comprehensive test suite for Signature Application"
echo "============================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js to run frontend tests."
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go to run backend tests."
    exit 1
fi

# Function to run frontend tests
run_frontend_tests() {
    print_status "Running frontend tests..."
    
    # Install dependencies if node_modules doesn't exist
    if [ ! -d "node_modules" ]; then
        print_status "Installing frontend dependencies..."
        npm install
    fi
    
    # Run linting
    print_status "Running ESLint..."
    if npm run lint; then
        print_success "Linting passed"
    else
        print_warning "Linting found issues (continuing with tests)"
    fi
    
    # Run unit tests with coverage
    print_status "Running frontend unit tests with coverage..."
    if npm run test:ci; then
        print_success "Frontend tests passed"
        return 0
    else
        print_error "Frontend tests failed"
        return 1
    fi
}

# Function to run backend tests
run_backend_tests() {
    print_status "Running backend tests..."
    
    cd submitImage
    
    # Download Go dependencies
    print_status "Downloading Go dependencies..."
    go mod download
    
    # Run Go tests with coverage
    print_status "Running Go unit tests with coverage..."
    if go test ./... -v -coverprofile=coverage.out; then
        print_success "Backend tests passed"
        
        # Generate coverage report
        if command -v go &> /dev/null; then
            print_status "Generating Go coverage report..."
            go tool cover -html=coverage.out -o coverage.html
            print_success "Coverage report generated: submitImage/coverage.html"
        fi
        
        cd ..
        return 0
    else
        print_error "Backend tests failed"
        cd ..
        return 1
    fi
}

# Function to run specific test suites
run_specific_tests() {
    case $1 in
        "frontend"|"fe"|"react"|"js"|"ts")
            run_frontend_tests
            ;;
        "backend"|"be"|"go"|"golang")
            run_backend_tests
            ;;
        "apple"|"auth")
            print_status "Running Apple authentication tests..."
            cd submitImage
            go test ./appleauth/... -v
            cd ..
            ;;
        "signature"|"canvas")
            print_status "Running signature-related tests..."
            npm test -- --testPathPattern="(Signature|Canvas)" --watchAll=false
            ;;
        "services")
            print_status "Running service tests..."
            npm test -- --testPathPattern="services" --watchAll=false
            ;;
        "components")
            print_status "Running component tests..."
            npm test -- --testPathPattern="components" --watchAll=false
            ;;
        *)
            print_error "Unknown test suite: $1"
            print_status "Available test suites:"
            echo "  - frontend, fe, react, js, ts: Frontend tests"
            echo "  - backend, be, go, golang: Backend tests"
            echo "  - apple, auth: Apple authentication tests"
            echo "  - signature, canvas: Signature-related tests"
            echo "  - services: Service layer tests"
            echo "  - components: React component tests"
            exit 1
            ;;
    esac
}

# Main execution
FRONTEND_RESULT=0
BACKEND_RESULT=0

if [ $# -eq 0 ]; then
    # Run all tests
    print_status "Running all tests..."
    
    run_frontend_tests
    FRONTEND_RESULT=$?
    
    run_backend_tests
    BACKEND_RESULT=$?
    
    # Summary
    echo ""
    echo "============================================================="
    echo "🧪 Test Results Summary"
    echo "============================================================="
    
    if [ $FRONTEND_RESULT -eq 0 ]; then
        print_success "Frontend tests: PASSED"
    else
        print_error "Frontend tests: FAILED"
    fi
    
    if [ $BACKEND_RESULT -eq 0 ]; then
        print_success "Backend tests: PASSED"
    else
        print_error "Backend tests: FAILED"
    fi
    
    if [ $FRONTEND_RESULT -eq 0 ] && [ $BACKEND_RESULT -eq 0 ]; then
        print_success "All tests passed! 🎉"
        exit 0
    else
        print_error "Some tests failed! 😞"
        exit 1
    fi
else
    # Run specific test suite
    run_specific_tests $1
fi