// --- Configuration et Dictionnaires ---

const SEPARATORS = ["", ".", "_", "-", "__"];
const SPECIAL_CHARS = ["!", "x", "X", "0", "~", "*", "+", "="];

// Dictionnaire pour le remplacement des caractères (Leet Speak)
const LEET_DICT = {
    'a': ['4', '@', 'A', '1'], 
    'e': ['3', 'E'], 
    'i': ['1', '!', 'I', 'x'],
    'o': ['0', 'O'], 
    's': ['5', '$', 'S'], 
    't': ['7', 'T'],
    'l': ['1', 'L'], 
    'g': ['9', 'G'], 
    'b': ['8', 'B']
};

// Configuration par défaut des plateformes populaires
const PLATFORM_PATTERNS = {
    "twitter": { max_length: 15, allow_dot: false, preferred_sep: "_" },
    "instagram": { max_length: 30, allow_dot: true, preferred_sep: "." },
    "tiktok": { max_length: 24, allow_dot: true, preferred_sep: "_" },
    "youtube": { max_length: 30, allow_dot: false, preferred_sep: "" },
    "twitch": { max_length: 25, allow_dot: false, preferred_sep: "_" },
    "discord": { max_length: 32, allow_dot: true, preferred_sep: "." },
    "generic": { max_length: 20, allow_dot: true, preferred_sep: "_" }
};

// --- Fonctions Utilitaires ---

function getRandomItem(arr) {
    if (!arr || arr.length === 0) return "";
    return arr[Math.floor(Math.random() * arr.length)];
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function createTypo(word) {
    if (!word || word.length < 4) return word;
    const idx = getRandomInt(1, word.length - 3);
    const arr = word.split('');
    const temp = arr[idx];
    arr[idx] = arr[idx + 1];
    arr[idx + 1] = temp;
    return arr.join('');
}

function getConsonants(word) {
    if (!word) return "";
    return word.toLowerCase().split('').filter(c => "bcdfghjklmnpqrstvwxz".includes(c)).join('');
}

function applySubstitution(word, targetChar = 'a', subChar = 'x') {
    if (!word) return "";
    const lower = word.toLowerCase();
    if (lower.includes(targetChar)) {
        return lower.split(targetChar).join(subChar);
    }
    return word;
}

function generateVariants(word, useTypos = true) {
    if (!word) return [""];
    word = word.toLowerCase();
    const variants = new Set([word]);
    
    variants.add(word[0]);
    if (word.length > 2) variants.add(word.substring(0, 2));
    if (word.length > 3) variants.add(word.substring(0, 3));
    
    const cons = getConsonants(word);
    if (cons) variants.add(cons);
    
    if (useTypos && word.length > 3) {
        variants.add(createTypo(word));
    }
    
    return Array.from(variants).filter(v => v !== "");
}

function applyLeet(text, intensity = 0.3) {
    if (!text) return text;
    let result = "";
    for (let char of text.toLowerCase()) {
        if (LEET_DICT[char] && Math.random() < intensity) {
            result += getRandomItem(LEET_DICT[char]);
        } else {
            result += char;
        }
    }
    return result;
}

function getRandomNoise() {
    const options = [
        getRandomInt(0, 99).toString(),
        getRandomItem(SPECIAL_CHARS),
        getRandomInt(0, 9).toString() + getRandomInt(0, 9).toString(),
        "x" + getRandomInt(0, 9)
    ];
    return getRandomItem(options);
}

// --- Logique Principale ---

function generateUsername(config) {
    const { 
        firstName, lastName, pseudo, decoyNumber, 
        platform = "generic", noiseLevel = 1,
        minLength = 0, maxLengthOverride = 0, forbiddenChars = "",
        requireNumber = false, requireSpecial = false
    } = config;

    const platformConfig = PLATFORM_PATTERNS[platform] || PLATFORM_PATTERNS["generic"];
    let sep = Math.random() > 0.3 ? platformConfig.preferred_sep : getRandomItem(SEPARATORS);
    if (!platformConfig.allow_dot && sep === ".") sep = "_";

    const first = (firstName || "").toLowerCase();
    const last = (lastName || "").toLowerCase();
    const psd = (pseudo || "").toLowerCase();
    const num = decoyNumber ? decoyNumber.toString() : "";

    const strategies = [];
    
    // Stratégie 1 : Combinaisons classiques
    const fVars = generateVariants(first);
    const lVars = generateVariants(last);
    const pVars = generateVariants(psd);
    
    const possibleComps = [];
    if (fVars.length) possibleComps.push(getRandomItem(fVars));
    if (lVars.length) possibleComps.push(getRandomItem(lVars));
    if (pVars.length) possibleComps.push(getRandomItem(pVars));
    
    let comp = possibleComps.filter(c => c);
    if (comp.length > 0) {
        // Shuffle and take up to 2
        comp.sort(() => 0.5 - Math.random());
        strategies.push(comp.slice(0, 2).join(sep));
    }

    // Stratégie 2 : Initiales + Séquence numérique
    if (first && last && num) {
        if (num.length >= 2) {
            strategies.push(`${first[0]}${num[0]}${last[0]}${num.substring(1)}`);
            strategies.push(`${num}${first[0]}${last[0]}`);
        } else {
            strategies.push(`${first[0]}${num}${last[0]}`);
        }
    }

    // Stratégie 3 : Substitution et Compression
    if (first) {
        let subName = applySubstitution(first, 'a', 'x');
        subName = applySubstitution(subName, 'i', '1');
        if (last) {
            strategies.push(`${subName}${getConsonants(last)}`);
        } else {
            strategies.push(`${subName}${getRandomNoise()}`);
        }
    }

    // Stratégie 4 : Leet Speak Ciblé
    if (first && last) {
        strategies.push(applyLeet(first + last, 0.5));
    } else if (psd) {
        strategies.push(applyLeet(psd, 0.5));
    }

    // Base finale du pseudonyme
    let baseName = strategies.length > 0 ? getRandomItem(strategies) : "user_" + getRandomNoise();
    
    // Ajout de bruit
    if (noiseLevel > 1 && Math.random() > 0.5) {
        const noise = getRandomNoise();
        baseName = Math.random() > 0.5 ? `${baseName}${noise}` : `${noise}${baseName}`;
    }

    // Nettoyage et Validation des Contraintes
    // Use string replacement properly instead of split/join which may err on empty string
    if (forbiddenChars) {
        for (let c of forbiddenChars) {
            baseName = baseName.split(c).join("");
        }
    }
        
    if (requireNumber && !/\d/.test(baseName)) {
        baseName += getRandomInt(0, 9).toString();
    }
        
    if (requireSpecial) {
        const allowedSpecials = SPECIAL_CHARS.filter(c => !forbiddenChars.includes(c));
        if (allowedSpecials.length > 0 && !allowedSpecials.some(c => baseName.includes(c))) {
            baseName += getRandomItem(allowedSpecials);
        }
    }
        
    while (baseName.length < minLength) {
        baseName += String.fromCharCode(97 + Math.floor(Math.random() * 26)); // random lowercase letter
    }
        
    const maxL = maxLengthOverride > 0 ? maxLengthOverride : platformConfig.max_length;
    if (baseName.length > maxL) baseName = baseName.substring(0, maxL);

    return baseName;
}

function generatePoisonBio(decoyCity, decoyHobbies, decoyPet) {
    const city = decoyCity || 'Paris';
    const hobbiesArr = decoyHobbies ? decoyHobbies.split(',').map(s => s.trim()).filter(s => s) : [];
    const hobby1 = hobbiesArr.length > 0 ? hobbiesArr[0] : 'le développement';
    const hobbySome = hobbiesArr.length > 0 ? hobbiesArr.slice(0, 2).join(', ') : 'Tech & Design';
    const pet = decoyPet || 'nature';

    const bios = [
        `Basé à ${city}. Passionné par ${hobby1}.`,
        `📍 ${city} | ${hobbySome}. Fan de ${pet}.`,
        `Amateur de ${hobby1} situé en ${city}.`
    ];
    return getRandomItem(bios);
}

// --- DOM Controller ---

document.addEventListener('DOMContentLoaded', () => {
    const generateBtn = document.getElementById('generate-btn');
    const exportBtn = document.getElementById('export-btn');
    const resultsContainer = document.getElementById('results-container');
    const resultsGrid = document.getElementById('results-grid');
    const bioOutput = document.getElementById('bio-output');
    const countInput = document.getElementById('config-count');

    let generatedResults = [];
    let currentBio = "";

    generateBtn.addEventListener('click', () => {
        // Collect values
        const config = {
            firstName: document.getElementById('info-first').value.trim(),
            lastName: document.getElementById('info-last').value.trim(),
            pseudo: document.getElementById('info-pseudo').value.trim(),
            decoyCity: document.getElementById('decoy-city').value.trim(),
            decoyHobbies: document.getElementById('decoy-hobbies').value.trim(),
            decoyNumber: document.getElementById('decoy-number').value.trim(),
            platform: document.getElementById('config-platform').value,
            minLength: parseInt(document.getElementById('config-min').value) || 0,
            maxLengthOverride: parseInt(document.getElementById('config-max').value) || 0,
            forbiddenChars: document.getElementById('config-forbidden').value.trim(),
            requireNumber: document.getElementById('config-req-num').checked,
            requireSpecial: document.getElementById('config-req-spec').checked,
            noiseLevel: 2 // hardcoded higher noise for variety
        };

        const count = parseInt(countInput.value) || 50;
        const usernames = new Set();
        let attempts = 0;
        const maxAttempts = count * 20;

        while (usernames.size < count && attempts < maxAttempts) {
            const name = generateUsername(config);
            if (name) usernames.add(name);
            attempts++;
        }

        generatedResults = Array.from(usernames);
        currentBio = generatePoisonBio(config.decoyCity, config.decoyHobbies, null);

        // Update UI
        renderResults();
    });

    function renderResults() {
        resultsContainer.classList.remove('hidden');
        resultsGrid.innerHTML = '';
        bioOutput.textContent = currentBio;

        generatedResults.forEach((name, i) => {
            const item = document.createElement('div');
            item.className = 'bg-[#0f141d] border border-[#1e2a38] rounded-md p-3 flex justify-between items-center group hover:border-[#00e5ff]/50 transition-colors';
            
            const nameSpan = document.createElement('span');
            nameSpan.className = 'font-mono text-[13px] text-[#cdd6e0] group-hover:text-[#00e5ff] transition-colors break-all';
            nameSpan.textContent = name;

            const copyBtn = document.createElement('button');
            copyBtn.className = 'text-[#5a7080] hover:text-white transition-colors opacity-0 group-hover:opacity-100 flex-shrink-0 ml-2';
            copyBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;
            copyBtn.onclick = () => {
                navigator.clipboard.writeText(name);
                copyBtn.classList.add('text-[#a0ff6e]');
                setTimeout(() => copyBtn.classList.remove('text-[#a0ff6e]'), 1000);
            };

            item.appendChild(nameSpan);
            item.appendChild(copyBtn);
            resultsGrid.appendChild(item);
        });
    }

    exportBtn.addEventListener('click', () => {
        if (generatedResults.length === 0) return;
        
        const timestamp = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '');
        let content = `--- GHOSTNAME EXPORT - ${timestamp} ---\n\n`;
        content += `BIO SUGGÉRÉE: ${currentBio}\n\n`;
        content += generatedResults.join('\n');

        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'ghostname_export.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });
});
