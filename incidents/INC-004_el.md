# INC-003: Επιμονή (Persistence) μέσω Scheduled Task στο WIN11-VICTIM

## Σύνοψη

| Πεδίο | Τιμή |
|---|---|
| **Αναγνωριστικό Περιστατικού** | INC-003 |
| **Ημερομηνία εντοπισμού** | 2026-10-22 |
| **Σοβαρότητα** | Χαμηλή |
| **Κατάσταση** | Επιλύθηκε (προσομοίωση σε lab) |
| **Εντοπίστηκε από** | Wazuh SIEM (rule 60228 – Scheduled Task Created) |
| **Αναλυτής** | Harry Kotsis |

## Εντοπισμός

Δημιουργήθηκε ένα νέο scheduled task στο μηχάνημα-θύμα με παραπλανητικό, φαινομενικά νόμιμο όνομα, ρυθμισμένο να εκτελεί μια κρυφή εντολή PowerShell σε καθημερινό πρόγραμμα — μια κλασική τεχνική επιμονής (persistence) που χρησιμοποιείται για τη διατήρηση πρόσβασης μετά από επανεκκινήσεις ή αποσυνδέσεις.

- **Rule ID:** 60228 — *"A scheduled task was created"* (Windows Event ID 4698)
- **Επίπεδο κανόνα:** 4
- **Μηχανισμός εντοπισμού:** Windows Security Auditing, υποκατηγορία *"Other Object Access Events"* (δεν είναι ενεργή εξ ορισμού· χρειάστηκε ρητή ενεργοποίηση μέσω `auditpol`)

## Πηγή και Στόχος

| Ρόλος | Hostname | Διεύθυνση IP |
|---|---|---|
| **Μηχάνημα** | WIN11-VICTIM | 192.168.56.20 |
| **Δημιουργήθηκε από** | τοπικό χρήστη (`vboxuser`), SID `S-1-5-21-3286371329-2178220117-4259111301-1000` | — |

## Τεχνική που Προσομοιώθηκε

Δημιουργήθηκε ένα scheduled task με όνομα **`WindowsUpdateCheck`** — σκόπιμα μιμούμενο ένα νόμιμο όνομα διαδικασίας Windows Update ώστε να μην τραβήξει την προσοχή — ρυθμισμένο ως εξής:

```
schtasks /create /tn "WindowsUpdateCheck" /tr "powershell.exe -WindowStyle Hidden -Command Get-Date" /sc daily /st 09:00
```

- **Trigger:** Καθημερινά, ξεκινώντας στις 09:00
- **Ενέργεια:** `powershell.exe -WindowStyle Hidden -Command Get-Date` (αβλαβές placeholder για τη δοκιμή· σε πραγματική επίθεση εδώ θα υπήρχε εντολή επανασύνδεσης σε C2 server, επανάληψη λήψης payload, ή επανεκτέλεση malware)
- **Στυλ παραθύρου:** Κρυφό, ώστε να μην εμφανιστεί κανένα ορατό παράθυρο που θα προειδοποιούσε τον χρήστη

## Αποδεικτικά Στοιχεία

- **Rule 60228** — *"A scheduled task was created"*, επίπεδο κανόνα 4
  - `data.win.eventdata.taskName`: `\WindowsUpdateCheck`
  - `data.win.eventdata.subjectUserName`: `vboxuser`
  - `data.win.eventdata.taskContent`: πλήρες XML του task, συμπεριλαμβανομένου του trigger (`CalendarTrigger`, `StartBoundary: 2026-10-22T09:00:00`), του δημιουργού (`WIN11-VICTIM\vboxuser`), και του προγράμματος (καθημερινά, διάστημα 1 ημέρας)
  - `rule.mitre.id`: **T1053**
  - `rule.mitre.tactic`: **Execution, Persistence, Privilege Escalation**
  - `rule.mitre.technique`: Scheduled Task/Job
- **Screenshots:**
  - `screenshots/04-persistence-wazuh-alert.png` — προβολή Threat Hunting, 1 hit στο Event ID 4698
  - `screenshots/04-persistence-alert-detail-1.png` — λεπτομέρειες, μεταδεδομένα task και πλήρες περιεχόμενο XML
  - `screenshots/04-persistence-alert-detail-2.png` — λεπτομέρειες, πεδία κανόνα και αντιστοίχιση MITRE ATT&CK

## Ανάλυση

Το προεπιλεγμένο ruleset του Wazuh εντόπισε και ταξινόμησε σωστά τη δημιουργία του scheduled task, και — αξιοσημείωτα — το σήμανε με **τρεις ταυτόχρονες τακτικές MITRE ATT&CK** (Execution, Persistence, Privilege Escalation) κάτω από μία μόνο τεχνική, το T1053 (Scheduled Task/Job). Αυτό αντικατοπτρίζει τη διπλή φύση των scheduled tasks: παρέχουν μηχανισμό τόσο για *εκτέλεση* κώδικα όσο και για *επιμονή* του μέσα στο χρόνο (επιβίωση σε restart/logoff), και — ανάλογα με το πλαίσιο εκτέλεσης του task (π.χ. ως `SYSTEM`) — μπορούν επίσης να αξιοποιηθούν για κλιμάκωση προνομίων (privilege escalation).

Ένα σημαντικό εύρημα είναι ότι **αυτός ο εντοπισμός ήταν δυνατός μόνο επειδή η σχετική υποκατηγορία ελέγχου (audit) των Windows είχε ενεργοποιηθεί ρητά εκ των προτέρων** (`auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`). Σε μια προεπιλεγμένη εγκατάσταση Windows 11, το Event ID 4698 δεν δημιουργείται καθόλου, πράγμα που σημαίνει ότι η επιμονή μέσω scheduled task θα ήταν εντελώς αόρατη σε ένα SIEM που βασίζεται μόνο στο προεπιλεγμένο auditing των Windows — ανεξάρτητα από το πόσο καλά ρυθμισμένοι είναι οι κανόνες εντοπισμού του ίδιου του SIEM. Αυτό αντικατοπτρίζει το ίδιο κενό ορατότητας (visibility gap) που είχε εντοπιστεί και στο INC-002 για το PowerShell Script Block Logging: **οι κανόνες εντοπισμού είναι τόσο καλοί όσο και οι πηγές logs που τους τροφοδοτούν.**

Το πλήρες XML του task που καταγράφηκε στο πεδίο `taskContent` παρείχε πλήρη ορατότητα στο τι θα εκτελούσε το task, πότε, και ως ποιος χρήστης — πληροφορία κρίσιμη σε μια πραγματική διερεύνηση για την εκτίμηση του πραγματικού payload και της έκτασης της επίπτωσης, αντί να βασιζόμαστε μόνο στο όνομα του task (το οποίο, όπως αποδείχθηκε εδώ, μπορεί να είναι σκόπιμα παραπλανητικό).

## Αντιστοίχιση MITRE ATT&CK

| Tactic | Technique | ID |
|---|---|---|
| Execution | Scheduled Task/Job | T1053.005 |
| Persistence | Scheduled Task/Job | T1053.005 |
| Privilege Escalation | Scheduled Task/Job | T1053.005 |

*(Το Wazuh ανέφερε τη γονική τεχνική T1053 μαζί με όλες τις εφαρμόσιμες τακτικές· το T1053.005 — το sub-technique ειδικά για Scheduled Task στα Windows — είναι η ακριβής αντιστοίχιση για αυτή τη συμπεριφορά.)*

## Προτεινόμενες Ενέργειες

1. Ενεργοποίηση της υποκατηγορίας ελέγχου *"Other Object Access Events"* (και σχετικού auditing scheduled tasks) ως **βασική ρύθμιση (baseline)** σε όλα τα παρακολουθούμενα endpoints Windows, όχι ως προαιρετική μεταγενέστερη προσθήκη.
2. Δημιουργία κανόνα active response ή ειδοποίησης στο Wazuh για σήμανση scheduled tasks των οποίων η ενέργεια περιλαμβάνει `powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, ή άλλα συνηθισμένα living-off-the-land binaries, ειδικά σε συνδυασμό με κρυφά στυλ παραθύρου ή κωδικοποιημένα ορίσματα.
3. Διατήρηση απογραφής/baseline των αναμενόμενων scheduled tasks ανά μηχάνημα, ώστε νέα tasks με άγνωστα ή ύποπτα γενικά ονόματα (π.χ. μίμηση "WindowsUpdate", "SystemCheck") να σημαίνονται για χειροκίνητη εξέταση.
4. Συσχέτιση γεγονότων δημιουργίας scheduled task με τη διεργασία-γονέα και τη συνεδρία σύνδεσης που τα δημιούργησε (`subjectLogonId`, `clientProcessId`), ώστε να διακρίνεται η νόμιμη διαχειριστική δραστηριότητα από επιμονή που προκαλείται από επιτιθέμενο.
5. Περιοδικός έλεγχος και αφαίρεση scheduled tasks που δημιουργήθηκαν εκτός εγκεκριμένων διαδικασιών διαχείρισης αλλαγών (change management).

## Διδάγματα (Σημειώσεις Lab)

- Το Windows Event ID 4698 (δημιουργία scheduled task) **δεν καταγράφεται εξ ορισμού** και απαιτεί ρητή ενεργοποίηση της υποκατηγορίας ελέγχου *"Other Object Access Events"* μέσω `auditpol`.
- Μετά την ενεργοποίηση του auditing, το αρχικό scheduled task χρειάστηκε να διαγραφεί και να ξαναδημιουργηθεί ώστε να παραχθεί αντίστοιχο event — οι αλλαγές στο auditing δεν εφαρμόζονται αναδρομικά σε ενέργειες που είχαν ήδη συμβεί.
- Ο πλήρης ορισμός XML του task (συμπεριλαμβανομένου του προγράμματος trigger και του δημιουργού) καταγράφηκε σε ένα και μόνο πεδίο γεγονότος (`taskContent`), προσφέροντας πλούσιο πλαίσιο χωρίς να χρειάζεται διασταύρωση πολλαπλών πηγών logs — μια αξιοσημείωτα βολική πτυχή αυτού του συγκεκριμένου event των Windows.
