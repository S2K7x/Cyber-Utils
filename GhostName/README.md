## GhostName | OSINT & Privacy Identity Generator

GhostName is a specialized Python utility designed to generate digital aliases that protect your privacy. By using **Leet Speak**, **data poisoning**, and **contextual variations**, it helps you create usernames that decouple your online presence from your real identity, effectively making OSINT (Open Source Intelligence) investigations much harder.

---

### Key Features

* **Advanced Anonymization**: Generates variants using typo-simulation, consonant extraction, and character substitution.
* **Platform-Specific Optimization**: Built-in rules for Twitter, Instagram, TikTok, Twitch, and Discord (length limits, allowed characters, etc.).
* **OSINT Deception**:
* **Data Poisoning**: Generates fake "Poison Bios" with decoy locations and hobbies.
* **Leet Speak Engine**: Randomly applies substitutions to bypass simple keyword searches.


* **Multi-Strategy Logic**: Combines real data fragments with decoy numbers and random "noise" characters.

---

### How the Generation Works

The tool uses four main strategies to transform your data:

1. **Classic Combinations**: Mixes fragments of your first name, last name, and habitual pseudo.
2. **Initial Sequences**: Combines initials with decoy numeric sequences.
3. **Compression**: Strips vowels and replaces key letters with "noise" (e.g., `jxm_doe`).
4. **Leet Transformation**: Converts letters to numbers or symbols based on an adjustable intensity level.

---

### Usage

#### 1. Running the script

Launch the interactive CLI to input your data and decoys:

```bash
python3 ghostname.py

```

#### 2. Workflow Summary

1. **Input Identity**: Enter the real names you want to protect.
2. **Add Decoys**: Provide a fake city, fake hobbies, and "decoy" years.
3. **Set Constraints**: Define character limits and mandatory symbols.
4. **Target Platform**: Select where the account will be used.
5. **Export**: Save your new identities to a text or JSON file.

---

### Configuration Options

| Feature | Description |
| --- | --- |
| **Leet Intensity** | Control how many letters are replaced by symbols. |
| **Noise Level** | Determine the amount of random characters added. |
| **Poison Bio** | Generates a fake profile description to mislead trackers. |
| **Platform Patterns** | Automatically adjusts naming conventions for specific social media. |
