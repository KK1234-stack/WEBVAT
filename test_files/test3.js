// Malicious: Inserting user input directly into DOM
let userInput = location.search.substring(1);
document.getElementById('output').innerHTML = userInput;

// Benign: Safe assignment to textContent
let safeContent = "Hello, user!";
document.getElementById('safe').textContent = safeContent;

// Malicious: use of eval()
let input = prompt("Enter JavaScript:");
eval(input);

// Benign: Strict JSON parsing
let safeData = JSON.parse('{"msg": "ok"}');
console.log(safeData);
