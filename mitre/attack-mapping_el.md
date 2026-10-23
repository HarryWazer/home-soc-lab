# Αντιστοίχιση MITRE ATT&CK — Home SOC Lab
Αυτό το αρχείο συγκεντρώνει τις τεχνικές MITRE ATT&CK που εντοπίστηκαν στα τέσσερα σενάρια επίθεσης αυτού του lab, με αναφορές στα αναλυτικά incident reports.
## Συγκεντρωτικός Πίνακας
| # | Σενάριο | Tactic | Technique | ID | Εντοπίστηκε από Wazuh; | Incident |
|---|---|---|---|---|---|---|
| 1 | Brute Force (RDP) | Credential Access | Brute Force: Password Guessing | T1110.001 | ✅ Ναι (rule 60122) | [INC-001](../incidents/INC-001_el.md) |
| 2 | Suspicious PowerShell | Discovery | Process Discovery | T1057 | ✅ Ναι (rule 91815) | [INC-002](../incidents/INC-002_el.md) |
| 2 | Suspicious PowerShell | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | ⚠️ Μερικώς (γενική τεχνική· δεν σημειώθηκε άμεσα από τον κανόνα) | [INC-002](../incidents/INC-002_el.md) |
| 2 | Suspicious PowerShell | Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | ❌ Όχι (χειροκίνητη αντιστοίχιση· δεν επιβεβαιώθηκε alert) | [INC-002](../incidents/INC-002_el.md) |
| 3 | Persistence | Execution | Scheduled Task/Job | T1053.005 | ✅ Ναι (rule 60228) | [INC-003](../incidents/INC-003_el.md) |
| 3 | Persistence | Persistence | Scheduled Task/Job | T1053.005 | ✅ Ναι (rule 60228) | [INC-003](../incidents/INC-003_el.md) |
| 3 | Persistence | Privilege Escalation | Scheduled Task/Job | T1053.005 | ✅ Ναι (rule 60228) | [INC-003](../incidents/INC-003_el.md) |
| 4 | Network Reconnaissance | Reconnaissance | Active Scanning: Scanning IP Blocks | T1595.001 | ❌ Όχι (κενό decoder, βλ. INC-004) | [INC-004](../incidents/INC-004_el.md) |
| 4 | Network Reconnaissance | Discovery | Network Service Discovery | T1046 | ❌ Όχι (κενό decoder, βλ. INC-004) | [INC-004](../incidents/INC-004_el.md) |
| 4 | Network Reconnaissance | Discovery | Remote System Discovery | T1018 | ❌ Όχι (κενό decoder, βλ. INC-004) | [INC-004](../incidents/INC-004_el.md) |
## Κάλυψη ανά Tactic
| Tactic | Τεχνικές που Καλύφθηκαν | Σενάρια |
|---|---|---|
| Reconnaissance | Active Scanning (T1595.001) | #4 |
| Discovery | Process Discovery (T1057), Network Service Discovery (T1046), Remote System Discovery (T1018) | #2, #4 |
| Execution | Command and Scripting Interpreter: PowerShell (T1059.001), Scheduled Task/Job (T1053.005) | #2, #3 |
| Persistence | Scheduled Task/Job (T1053.005) | #3 |
| Privilege Escalation | Scheduled Task/Job (T1053.005) | #3 |
| Credential Access | Brute Force: Password Guessing (T1110.001), OS Credential Dumping: LSASS Memory (T1003.001) | #1, #2 |
## Σύνοψη Ποσοστού Εντοπισμού
Από τις **10 περιπτώσεις τεχνικών** που αντιστοιχίστηκαν στα τέσσερα σενάρια:
- **5** εντοπίστηκαν πλήρως από το προεπιλεγμένο ruleset του Wazuh (brute force, process discovery, και όλες οι τρεις τακτικές του event επιμονής μέσω scheduled task)
- **1** καλύφθηκε μερικώς (εκτέλεση PowerShell — εντοπίστηκε έμμεσα, χωρίς να σημειωθεί με τη δική της συγκεκριμένη τεχνική MITRE από τον κανόνα που ταίριαξε)
- **4** **δεν εντοπίστηκαν**, χωρισμένες σε δύο διακριτές βασικές αιτίες:
  - **Κενό ρύθμισης** (ορατότητα μη ενεργοποιημένη εξ ορισμού): αναγνώριση πρόσβασης credentials μέσω LSASS στο INC-002 — το Script Block Logging κατέγραψε την εντολή αλλά κανένας συγκεκριμένος κανόνας δεν σήμανε το ίδιο το μοτίβο πρόσβασης στο LSASS
  - **Κενό decoder** (το log συλλέχθηκε αλλά δεν αναλύθηκε/ευρετηριάστηκε): και οι τρεις τεχνικές αναγνώρισης στο INC-004 — το Windows Firewall log διαβαζόταν ενεργά από τον agent αλλά δεν υπήρχε decoder στην πλευρά του server για να το ερμηνεύσει
## Κεντρικό Συμπέρασμα
Αυτό το lab αποδεικνύει ότι **η κάλυψη εντοπισμού δεν είναι δυαδική** — ένα SIEM μπορεί να έχει εξαιρετικούς, out-of-the-box κανόνες για κάποιες πηγές logs (Windows Event Log μέσω `eventchannel`, όπως φάνηκε στα INC-001–INC-003) ενώ έχει **μηδενική κάλυψη** για άλλες (native text-based logs όπως το `pfirewall.log`, όπως φάνηκε στο INC-004), ακόμα και όταν η υποκείμενη τηλεμετρία συλλέγεται κανονικά. Η επαλήθευση του εντοπισμού από άκρη σε άκρη (δημιουργία event → επιβεβαίωση ότι καταγράφεται → επιβεβαίωση ότι συλλέγεται → επιβεβαίωση ότι αναλύεται → επιβεβαίωση ότι δημιουργεί alert) είναι απαραίτητη πριν εμπιστευτείς οποιονδήποτε μηχανισμό παρακολούθησης, αντί να υποθέτεις ότι "ο agent τρέχει" ή "η πηγή log είναι ενεργοποιημένη" είναι αρκετό.
