# DNS server — work in progress

Progetto didattico in C per Linux. La versione attuale è un **forwarder DNS UDP**:
accetta query locali, le inoltra a un resolver configurabile e restituisce la
risposta al client. La risoluzione iterativa autonoma dai root server è ancora
incompleta: le bozze sono conservate in `experiments/`, escluse dalla build.

## Requisiti e compilazione

Linux (usa `epoll` e `timerfd`), un compilatore C11, Make, pkg-config e ldns.
Su Debian/Ubuntu:

```sh
sudo apt install build-essential pkg-config libldns-dev python3 dnsutils
make
```

`python3` serve per i test; `dnsutils` fornisce `dig` per le prove manuali.
Il programma compilato è `./main`. `make clean` rimuove gli oggetti;
`make fclean` rimuove anche l'eseguibile; `make re` ricompila da zero.

## Avvio

```sh
./main
```

Per impostazione predefinita ascolta su **127.0.0.1:5353** e inoltra a
**1.1.1.1:53**. Non richiede root. Per interrogare il resolver pubblico è
necessaria connettività UDP verso Internet.

```sh
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com AAAA
```

Configurazione posizionale:

```sh
./main [porta-locale [ipv4-upstream [porta-upstream]]]
./main 8053 8.8.8.8 53
./main --help
```

Il bind rimane su loopback IPv4. Le porte inferiori a 1024 possono richiedere
privilegi aggiuntivi. Arresto con `Ctrl+C` oppure `SIGTERM`.

## Cosa funziona

- Un event loop con socket non bloccanti, `epoll` e `timerfd`.
- Parsing dei pacchetti con ldns e una domanda per query.
- Pool fino a 8192 query pendenti, ID upstream separati e ripristino dell'ID client.
- Inoltro del pacchetto originale, inclusa l'eventuale opzione EDNS ammessa;
  conservazione dei codici di risposta upstream, incluso NXDOMAIN.
- Socket upstream connesso al resolver selezionato e controllo di nome, tipo
  e classe della domanda prima di accettarne la risposta.
- Timeout di circa due secondi con risposta SERVFAIL e rilascio delle risorse.
- Risposte FORMERR/NOTIMP per richieste malformate o operazioni non supportate;
  datagrammi troppo corti, troppo grandi o già marcati come risposta sono scartati.

## Test

```sh
make test
```

I test non richiedono Internet: avviano un resolver UDP simulato su loopback e
verificano inoltro A/AAAA, ID, NXDOMAIN, rifiuto di risposte con domanda diversa,
input malformato, timeout ripetuti, ripresa del servizio e arresto pulito.
Un test C controlla anche scadenze, cancellazione e cascata della timing wheel.
GitHub Actions esegue build e test a ogni push e pull request.

## Struttura

- `src/main.c`: configurazione, inizializzazione e arresto.
- `src/worker/`: ricezione query, event loop e timeout.
- `src/handle_upstream_response.c`: verifica e inoltro delle risposte.
- `src/Hierarchical_Timing_Wheel/`: timer delle query pendenti.
- `src/utils/`: pool di contesti e ID, utility e stampa DNS.
- `src/logger/`, `include/`: logging e dichiarazioni condivise.
- `tests/`: test automatici locali.
- `experiments/`: bozze storiche, incomplete e non compilate dal Makefile.

## Limiti e prossimi passi

È un prototipo per sviluppo locale, non un resolver pronto per produzione.
Non implementa cache, risoluzione iterativa completa, validazione DNSSEC,
TCP o fallback TCP per risposte troncate, trasporto IPv6, DoT/DoH,
retry/failover tra resolver, rate limiting o worker multipli.
Il buffer UDP è limitato a 4096 byte; le query con QNAME compresso non sono
accettate e viene ammesso al massimo un record addizionale.
Quando il pool è esaurito le nuove richieste vengono scartate.
Gli ID usano uno shuffle pseudocasuale non crittografico.
Le priorità successive sono completare la risoluzione iterativa, aggiungere
cache e fallback TCP, poi irrobustire la gestione del carico.
