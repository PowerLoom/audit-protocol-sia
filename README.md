# Audit Protocol using

## Write up
[![Preview](/preview.png)](./AuditProtocol-SkyDB-Hackaton2020.pdf)

## Demo Video

1. [YouTube](https://www.youtube.com/watch?v=QdtEz7m9zRg)
2. [Skynet](https://siasky.net/AAAM_0-rOhnO4hyTR2Ig2Gg4eNuzqiwphcVcSUDt0T_5nw)

## Backend

### Setup

1. `pip install -r requirements.txt`
2. Setup account and deploy [contract](./AuditRecordStore.sol) on [MaticVigil](https://maticvigil.com/docs/)
3. Setup redis.
4. Clone [`settings.example.json`](./settings.example.json) to `settings.json`.
5. Bring up (or remotely forward) the Sia daemon to `localhost:9980`

### Scripts to Run

1. `uvicorn main:app --port 9000`

## [>> Setting up Frontend](./frontend/README.md)
