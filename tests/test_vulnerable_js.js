/**
 * This file contains intentional vulnerabilities for testing CodeGuardian.
 * DO NOT USE THIS CODE IN PRODUCTION!
 */

// Hardcoded credentials (vulnerability)
const DB_USERNAME = "admin";
const DB_PASSWORD = "super_secret_password123";
const API_KEY = "1234567890abcdef";

// Insecure JWT configuration
const jwt = require('jsonwebtoken');
const JWT_SECRET = "hardcoded_secret_key";

/**
 * Process user input and update the DOM.
 * @param {string} userInput - User-provided input
 */
function processUserInput(userInput) {
    // XSS vulnerability
    document.getElementById('output').innerHTML = userInput; // Vulnerable to XSS
    
    // Another XSS vulnerability
    document.write("<div>" + userInput + "</div>"); // Vulnerable to XSS
}

/**
 * Execute code from a string.
 * @param {string} codeString - String containing code to execute
 */
function executeCode(codeString) {
    // Code execution vulnerability
    eval(codeString); // Vulnerable to code execution
    
    // Another code execution vulnerability
    setTimeout("console.log('" + codeString + "')", 1000); // Vulnerable to code execution
}

/**
 * Generate a random token.
 * @returns {number} A random token
 */
function generateToken() {
    // Insecure randomness
    return Math.random() * 1000000; // Not cryptographically secure
}

/**
 * Set a cookie with user information.
 * @param {string} username - The username to store
 */
function setUserCookie(username) {
    // Insecure cookie
    document.cookie = "username=" + username; // Missing secure and httpOnly flags
}

/**
 * Merge user data with defaults.
 * @param {object} userData - User-provided data
 * @returns {object} Merged data
 */
function mergeUserData(userData) {
    // Prototype pollution vulnerability
    const defaults = { role: 'user', permissions: [] };
    return Object.assign({}, defaults, userData); // Vulnerable to prototype pollution
}

/**
 * Validate a regular expression.
 * @param {string} input - User input to validate
 * @returns {boolean} Whether the input is valid
 */
function validateInput(input) {
    // ReDoS vulnerability
    const regex = new RegExp("^(a+)+$"); // Vulnerable to ReDoS
    return regex.test(input);
}

/**
 * Configure CORS for an API.
 * @param {object} res - Response object
 */
function configureCORS(res) {
    // Insecure CORS configuration
    res.header("Access-Control-Allow-Origin", "*"); // Allows any origin
}

/**
 * Create a function from a string.
 * @param {string} functionBody - Function body as a string
 * @returns {Function} The created function
 */
function createFunction(functionBody) {
    // Insecure function creation
    return new Function(functionBody); // Similar to eval
}

/**
 * Debug logging.
 * @param {string} message - Message to log
 */
function debugLog(message) {
    // Debug information leak
    console.log("DEBUG: " + message); // Should not be in production code
}

/**
 * Main function.
 */
function main() {
    console.log("Running vulnerable JavaScript code...");
    
    // Call vulnerable functions
    processUserInput("<script>alert('XSS')</script>");
    executeCode("console.log('Executing arbitrary code')");
    
    const token = generateToken();
    console.log(`Generated token: ${token}`);
    
    setUserCookie("admin");
    
    const userData = { name: "User", role: "admin" };
    const mergedData = mergeUserData(userData);
    console.log(mergedData);
    
    validateInput("aaaaaaaaaaaaaaaaaaaaaaaa");
    
    // Mock response object for demonstration
    const res = { header: function(name, value) { console.log(`Setting header ${name}=${value}`); } };
    configureCORS(res);
    
    const dynamicFunction = createFunction("return 'This is dangerous';");
    console.log(dynamicFunction());
    
    debugLog("This is a debug message");
}

// Call main function
main(); 