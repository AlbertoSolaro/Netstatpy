# Installazione

Entrambi sono scritti in __Python__ ed in particolare è necessaria come requisito minimo la sua versione __3.7__. Per l'installazione dei moduli necessari al funzionamento dei diversi programmi si utilizzerà il gestore dei pacchetti python __pip3__.

## Prerequisiti

### Python 3.7

Per installare __Python 3.7__ si può procedere nel seguente modo su sistemi operativi Windows:

- Scaricare il binario presente sul sito https://www.python.org/downloads/
- Installare l'eseguibile facendo attenzione ad aggiungere il percorso di installazione nelle variabili di sistema.

Invece per sistemi operativi basati su Linux che utilizzano il gestore dei pacchetti __apt__, come la distribuzione Debian:

```bash
apt-get install python3.7
```

### Pip3

Il gestore dei pacchetti __pip3__ nei sistemi che hanno installato __python 3.7__ tramite il download dell'eseguibile è già compreso. Invece per i sistemi operativi Linux, va eseguito il seguente comando:
```bash  
apt-get install python3-pip
```

### Dipendenze

In entrambi i software è presente nella radice della cartella un file denominato __requirements.txt__, questo contiene i diversi moduli python necessari al funzionamento di essi. Questa operazione va eseguita dopo i passaggi per l'installazione dei due programmi.

Per entrambi è sufficiente avere a disposizione un terminale e spostarsi nella cartella del software da installare e lanciare il seguente comando:

```bash
pip install -r requirements.txt
```

Questa operazione va ripetuta in entrambe le cartelle dei due programmi.

### Ambiente di analisi

Per creare un ambiente di analisi è necessario che entrambi gli strumenti sia presenti all'interno della stessa cartella e le operazioni che richiamo i due programmi vengano eseguiti all'interno di essa.

Il nome della cartella può essere totalmente arbitrario, in queste Sezioni di Manuale verrà utilizzato il nome __envtest__.

## Netstatpy 

Per installare _netstatpy_ è necessario possedere la cartella __netstatpy__ allegata a questa tesi, contenente il software e successivamente bisogna seguire questi passaggi:
- copiare la cartella nell'ambiente di analisi, come spiegato nella Sezione \re{env}, nell'esempio __envtest__;
- installare le dipendenze come illustrato in \ref{dep}.

# Utilizzo
Per verificare l'installazione è possibile lanciare il seguente comando nell'ambiente di analisi:

```bash
python -m netstatpy -h
```

Questo comando restituirà, se il programma è correttamente installato, il manuale da linea di comando dove vengono elencate le varie opzioni con cui può essere eseguito e una breve spiegazione.

Per eseguire il programma con le diverse opzioni bisogna utilizzare il seguente comando:

```bash
python -m netstatpy [-h] [-p PCAP_FILE] [-o [OUTPUT_FILE]] [-t [THREAD]] [-s STEP] [--live] IP_HOST
```

Dove l'argomento posizionale relaltivo all'indirizzo IP dell'host è obbligatorio, mentre gli altri sono opzionali. Di seguito vengono descritte le diverse opzioni possibili:

```
 -h, --help:	mostra il messaggio d'aiuto ed termina l'esecuzione.
```

```
IP_HOST:	IP dell'host con cui viene fatta la cattura.
```

Questo viene utilizzato per filtrare i diversi pacchetti di rete che non possiedono l'intestazione IP (es. ARP) e di tenere solamente i pacchetti relativi all'indirizzo IP sull'interfaccia desiderata.

```
--live:	analisi live.
```

Questa opzione abilita la cattura sull'interfaccia di rete principale e ne elabora i diversi pacchetti raccolti in tempo reale.

```
-p PCAP_FILE:	nella modalità live è usata per salvare la sessione, in modalità normale è usata come sessione da analizzare.
```

Questa opzione ha due comportamenti distinti in base al contesto nel quale viene utilizzato, nel caso di una analisi live questo rappresenta il percorso del file nel quale la sessione catturata verrà salvata. Invece in un analisi offline rappresenta il percorso del file pcap da utilizzare per essa.

```
-o [OUTPUT_FILE]:	salvare le statistiche su file. \verb+OUTPUT_FILE+ è opzionale.
```

Questa opzione permette di specificare che l'output dell'analisi vada salvato all'interno di un file sul filesystem, perchè altrimenti il comportamento di base è la stampa delle statistiche sul terminale. Con la sola opzione attivata viene automaticamente generato un file con un nome di default contenente la data e l'ora dell'analisi, altrimenti è possibile specificare il percorso del file nel quale salvare l'analisi.

```
-t [THREAD]:	numero di thread usati, ignorato se analisi live. Se mancante viene utilizzato un singolo thread. Se \verb+[THREAD]+ non specificato il valore di default è 3.
```

Questa opzione permette di indicare se parallelizzare il calcolo dell'analisi, nel caso di analisi live questo non è possibile, ma per analisi su pacchetti pcap è possibile lasciar suddividere al programma in maniera autonoma i diversi pacchetti per velocizzare l'analisi. (Test effettuati fino ad un massimo di 12 thread)

```
-s STEP:	step usati per l'analisi. Default: 5.
```

Grazie a questa opzione è possibile selezionare ogni quanti pacchetti di un determinato flusso è possibile estrarre una statistica. Si consideri che per ogni step verrà creato un dato nell'insieme di output e questo conterrà le statistiche sull'intero flusso fino l'ultimo pacchetto analizzato di esso.