SUSPICIOUS_COMMANDS = [
    "wget",
    "curl",
    "chmod",
    "bash",
    "sh",
    "nc",
    "netcat",
    "python",
    "perl",
    "busybox",
    "powershell",
    "scp",
    "tftp"
]

RECON_COMMANDS = [
    "ls",
    "pwd",
    "whoami",
    "id",
    "ps",
    "uname -a",
    "cat /etc/passwd"
]

DOWNLOAD_COMMANDS = [
    "wget",
    "curl",
    "scp",
    "tftp"
]

EXECUTION_COMMANDS = [
    "bash",
    "sh",
    "chmod",
    "python",
    "perl",
    "busybox"
]

COMMON_BAD_PASSWORDS = [
    "admin",
    "root",
    "123456",
    "password",
    "toor",
    "1234",
    "ubuntu"
]


def sanitize_password(password: str | None) -> str | None:
    if password is None:
        return None

    cleaned = "".join(ch for ch in password if ch.isprintable())
    cleaned = cleaned.strip()

    if not cleaned:
        return "(vide)"

    return cleaned


def compute_score(username: str | None, password: str | None, commands: list[str]) -> int:
    score = 0
    cleaned_password = sanitize_password(password)

    if username and username.lower() == "root":
        score += 10

    if cleaned_password and cleaned_password.lower() in COMMON_BAD_PASSWORDS:
        score += 20

    if cleaned_password == "(vide)":
        score += 5

    suspicious_count = 0

    for cmd in commands:
        cmd_lower = cmd.lower()

        for suspicious in SUSPICIOUS_COMMANDS:
            if suspicious in cmd_lower:
                suspicious_count += 1
                break

    score += suspicious_count * 15

    if len(commands) >= 3:
        score += 10

    if len(commands) >= 6:
        score += 10

    if suspicious_count >= 3:
        score += 15

    return min(score, 100)


def score_to_label(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def classify_attack(username: str | None, password: str | None, commands: list[str]) -> str:
    cleaned_password = sanitize_password(password)
    joined = " ".join(commands).lower()

    download_hits = sum(
        1 for cmd in commands
        for keyword in DOWNLOAD_COMMANDS
        if keyword in cmd.lower()
    )

    execution_hits = sum(
        1 for cmd in commands
        for keyword in EXECUTION_COMMANDS
        if keyword in cmd.lower()
    )

    recon_hits = sum(
        1 for cmd in commands
        for keyword in RECON_COMMANDS
        if keyword in cmd.lower()
    )

    if execution_hits >= 1 and download_hits >= 1:
        return "tentative malware"

    if execution_hits >= 1:
        return "tentative d'exécution"

    if download_hits >= 1:
        return "tentative de téléchargement"

    if recon_hits >= 3:
        return "reconnaissance"

    if username and username.lower() == "root" and cleaned_password in COMMON_BAD_PASSWORDS:
        return "brute force probable"

    if len(commands) >= 5:
        return "activité suspecte"

    return "interaction simple"