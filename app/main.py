from collections import Counter

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine
from app.models import CommandLog, SessionAttack
from app.services.scoring import (
    classify_attack,
    sanitize_password,
    score_to_label,
)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Honeypot Dashboard")
templates = Jinja2Templates(directory="app/templates")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/sessions")
def get_sessions(db: Session = Depends(get_db)):
    sessions = db.query(SessionAttack).order_by(SessionAttack.timestamp.desc()).all()

    result = []
    for s in sessions:
        commands = db.query(CommandLog).filter(CommandLog.session_id == s.id).all()
        command_list = [cmd.command for cmd in commands]

        result.append(
            {
                "id": s.id,
                "timestamp": s.timestamp.isoformat(),
                "ip_source": s.ip_source,
                "username": s.username,
                "password": sanitize_password(s.password),
                "success": s.success,
                "threat_score": s.threat_score,
                "threat_label": score_to_label(s.threat_score),
                "attack_type": classify_attack(s.username, s.password, command_list),
                "commands": command_list,
            }
        )

    return result


@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total_sessions = db.query(SessionAttack).count()
    avg_score = db.query(func.avg(SessionAttack.threat_score)).scalar() or 0

    top_ips = (
        db.query(SessionAttack.ip_source, func.count(SessionAttack.id).label("count"))
        .group_by(SessionAttack.ip_source)
        .order_by(func.count(SessionAttack.id).desc())
        .limit(5)
        .all()
    )

    top_usernames = (
        db.query(SessionAttack.username, func.count(SessionAttack.id).label("count"))
        .group_by(SessionAttack.username)
        .order_by(func.count(SessionAttack.id).desc())
        .limit(5)
        .all()
    )

    top_passwords_raw = (
        db.query(SessionAttack.password, func.count(SessionAttack.id).label("count"))
        .group_by(SessionAttack.password)
        .order_by(func.count(SessionAttack.id).desc())
        .all()
    )

    cleaned_password_counter = Counter()
    for password, count in top_passwords_raw:
        cleaned_password_counter[sanitize_password(password)] += count

    top_commands = (
        db.query(CommandLog.command, func.count(CommandLog.id).label("count"))
        .group_by(CommandLog.command)
        .order_by(func.count(CommandLog.id).desc())
        .limit(5)
        .all()
    )

    all_sessions = db.query(SessionAttack).all()
    attack_counter = Counter()

    for session in all_sessions:
        commands = db.query(CommandLog).filter(CommandLog.session_id == session.id).all()
        command_list = [cmd.command for cmd in commands]
        attack_counter[classify_attack(session.username, session.password, command_list)] += 1

    return {
        "total_sessions": total_sessions,
        "average_score": round(float(avg_score), 2),
        "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips if ip],
        "top_usernames": [{"username": username, "count": count} for username, count in top_usernames if username],
        "top_passwords": [{"password": password, "count": count} for password, count in cleaned_password_counter.most_common(5)],
        "top_commands": [{"command": command, "count": count} for command, count in top_commands if command],
        "attack_types": [{"type": attack_type, "count": count} for attack_type, count in attack_counter.most_common()],
    }


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    sessions = (
        db.query(SessionAttack)
        .order_by(SessionAttack.timestamp.desc())
        .limit(20)
        .all()
    )

    formatted_sessions = []

    for session in sessions:
        commands = db.query(CommandLog).filter(CommandLog.session_id == session.id).all()
        command_list = [cmd.command for cmd in commands]

        formatted_sessions.append({
            "id": session.id,
            "timestamp": session.timestamp,
            "ip_source": session.ip_source,
            "username": session.username,
            "password": sanitize_password(session.password),
            "threat_score": session.threat_score,
            "threat_label": score_to_label(session.threat_score),
            "attack_type": classify_attack(session.username, session.password, command_list),
            "commands": command_list
        })

    total_sessions = db.query(SessionAttack).count()

    avg_score = db.query(func.avg(SessionAttack.threat_score)).scalar() or 0
    avg_score = round(float(avg_score), 2)

    top_ips = (
        db.query(SessionAttack.ip_source, func.count(SessionAttack.id).label("count"))
        .group_by(SessionAttack.ip_source)
        .order_by(func.count(SessionAttack.id).desc())
        .limit(5)
        .all()
    )

    top_usernames = (
        db.query(SessionAttack.username, func.count(SessionAttack.id).label("count"))
        .group_by(SessionAttack.username)
        .order_by(func.count(SessionAttack.id).desc())
        .limit(5)
        .all()
    )

    top_passwords_raw = (
        db.query(SessionAttack.password, func.count(SessionAttack.id).label("count"))
        .group_by(SessionAttack.password)
        .order_by(func.count(SessionAttack.id).desc())
        .all()
    )

    cleaned_password_counter = Counter()
    for password, count in top_passwords_raw:
        cleaned_password_counter[sanitize_password(password)] += count

    top_commands = (
        db.query(CommandLog.command, func.count(CommandLog.id).label("count"))
        .group_by(CommandLog.command)
        .order_by(func.count(CommandLog.id).desc())
        .limit(5)
        .all()
    )

    all_sessions = db.query(SessionAttack).all()
    attack_counter = Counter()

    for session in all_sessions:
        commands = db.query(CommandLog).filter(CommandLog.session_id == session.id).all()
        command_list = [cmd.command for cmd in commands]
        attack_counter[classify_attack(session.username, session.password, command_list)] += 1

    medium_count = db.query(SessionAttack).filter(SessionAttack.threat_score >= 30, SessionAttack.threat_score < 60).count()
    high_count = db.query(SessionAttack).filter(SessionAttack.threat_score >= 60, SessionAttack.threat_score < 80).count()
    critical_count = db.query(SessionAttack).filter(SessionAttack.threat_score >= 80).count()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "sessions": formatted_sessions,
            "total_sessions": total_sessions,
            "average_score": avg_score,
            "top_ips": top_ips,
            "top_usernames": top_usernames,
            "top_passwords": cleaned_password_counter.most_common(5),
            "top_commands": top_commands,
            "attack_types": attack_counter.most_common(),
            "medium_count": medium_count,
            "high_count": high_count,
            "critical_count": critical_count,
        }
    )


@app.get("/report/txt", response_class=PlainTextResponse)
def report_txt(db: Session = Depends(get_db)):
    sessions = db.query(SessionAttack).order_by(SessionAttack.timestamp.desc()).all()
    commands = db.query(CommandLog).all()

    total_sessions = len(sessions)
    avg_score = round(sum(s.threat_score for s in sessions) / total_sessions, 2) if total_sessions else 0

    ip_counter = Counter(s.ip_source for s in sessions if s.ip_source)
    username_counter = Counter(s.username for s in sessions if s.username)
    password_counter = Counter(sanitize_password(s.password) for s in sessions)
    command_counter = Counter(c.command for c in commands if c.command)

    attack_counter = Counter()
    for session in sessions:
        session_commands = db.query(CommandLog).filter(CommandLog.session_id == session.id).all()
        command_list = [cmd.command for cmd in session_commands]
        attack_counter[classify_attack(session.username, session.password, command_list)] += 1

    report_lines = [
        "Rapport Honeypot SSH",
        "====================",
        "",
        "1. Résumé",
        "---------",
        f"Nombre total de sessions capturées : {total_sessions}",
        f"Score moyen de menace : {avg_score}/100",
        f"Sessions medium : {sum(1 for s in sessions if 30 <= s.threat_score < 60)}",
        f"Sessions high : {sum(1 for s in sessions if 60 <= s.threat_score < 80)}",
        f"Sessions critical : {sum(1 for s in sessions if s.threat_score >= 80)}",
        "",
        "2. Types d'attaque observés",
        "---------------------------",
    ]

    if attack_counter:
        for attack_type, count in attack_counter.most_common():
            report_lines.append(f"- {attack_type} : {count} session(s)")
    else:
        report_lines.append("- Aucune donnée")

    report_lines.extend([
        "",
        "3. Top IP",
        "---------",
    ])

    if ip_counter:
        for ip, count in ip_counter.most_common(5):
            report_lines.append(f"- {ip} : {count} session(s)")
    else:
        report_lines.append("- Aucune donnée")

    report_lines.extend([
        "",
        "4. Top usernames",
        "----------------",
    ])

    if username_counter:
        for username, count in username_counter.most_common(5):
            report_lines.append(f"- {username} : {count} tentative(s)")
    else:
        report_lines.append("- Aucune donnée")

    report_lines.extend([
        "",
        "5. Top mots de passe",
        "--------------------",
    ])

    if password_counter:
        for password, count in password_counter.most_common(5):
            report_lines.append(f"- {password} : {count} tentative(s)")
    else:
        report_lines.append("- Aucune donnée")

    report_lines.extend([
        "",
        "6. Top commandes",
        "----------------",
    ])

    if command_counter:
        for command, count in command_counter.most_common(10):
            report_lines.append(f"- {command} : {count} occurrence(s)")
    else:
        report_lines.append("- Aucune donnée")

    report_lines.extend([
        "",
        "7. Dernières sessions",
        "---------------------",
    ])

    if sessions:
        for s in sessions[:10]:
            session_commands = db.query(CommandLog).filter(CommandLog.session_id == s.id).all()
            command_list = [cmd.command for cmd in session_commands]
            report_lines.append(
                f"- ID={s.id} | Date={s.timestamp} | IP={s.ip_source} | User={s.username} | Password={sanitize_password(s.password)} | Score={s.threat_score}/100 | Niveau={score_to_label(s.threat_score)} | Type={classify_attack(s.username, s.password, command_list)}"
            )
    else:
        report_lines.append("- Aucune session enregistrée")

    report_lines.extend([
        "",
        "8. Conclusion",
        "-------------",
        "Le honeypot a permis d'observer les identifiants testés, les commandes envoyées et le type probable de comportement malveillant.",
        "Le score a été normalisé sur 100 pour simplifier l'analyse et rendre la lecture plus claire.",
    ])

    return "\n".join(report_lines)