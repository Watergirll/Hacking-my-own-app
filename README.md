# Deskly — v2-secure

Aplicație web pentru managementul incidentelor IT.  
Această versiune conține vulnerabilități introduse **intenționat** pentru scopuri educaționale (ethical hacking lab).

---

## Pornire rapidă

```bash
# 1. Clonează repo-ul pe branch-ul vulnerabil
git clone -b v2-secure https://github.com/Watergirll/Hacking-my-own-app.git deskly-v2
cd deskly

# 2. Build și pornire containere

docker compose up -d --build

# 3. Verifică starea
docker compose ps
```

Aplicația rulează la **[http://localhost:80](http://localhost:80)**

---

## Comenzi utile

### Pornire / Oprire

```bash
# Pornire în background
docker compose up -d

# Oprire (păstrează datele)
docker compose stop

# Oprire și ștergere containere (păstrează volumul DB)
docker compose down

# Logs în timp real
docker compose logs -f backend
```

### Reset bază de date

```bash
# Oprire completă + ștergere volum (ȘTERGE TOATE DATELE)
docker compose down -v

# Repornire — DB se reinițializează automat din schema.sql
docker compose up -d
```

---

Aplicatia vulnerabila este pe branch-ul `v1-vulnerable`.