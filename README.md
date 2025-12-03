AWS Email-to-SFTP Pipeline

Pipeline that extracts email attachments from Office 365, sends them to AWS (API Gateway → Lambda → S3), and uses S3 events to trigger a second Lambda that delivers files to SFTP destinations.

```mermaid
flowchart TD

    %% Inbound email side
    subgraph Email_Source["Email Source"]
        O365["Office 365 / Exchange Online"]
        PA["Power Automate Flow (HTTP POST)"]
        O365 --> PA
    end

    PA -->|"HTTP POST (file + metadata)"| APIGW["Amazon API Gateway"]

    subgraph AWS["Amazon Web Services"]
        APIGW -->|"Invoke"| L1["Lambda #1 (email_to_s3)"]
        L1 -->|"Store object"| S3["S3 Bucket (raw email files)"]
        S3 -->|"S3 Put event"| L2["Lambda #2 (s3_to_sftp)"]

        SSM["SSM Parameter Store (routing rules)"]
        SSM -->|"Load routing patterns"| L2
    end

    %% SFTP destinations
    L2 -->|"SFTP upload (SSH)"| SFTP1["SFTP Server: /reports/daily"]
    L2 -->|"SFTP upload (SSH)"| SFTP2["SFTP Server: /reports/intraday"]

```
## Power Automate flow

The email ingestion logic is implemented in a Power Automate flow that:

- Watches a dedicated Office 365 mailbox
- Filters emails and attachments based on business rules
- Sends each attachment to API Gateway via HTTP POST (binary body + metadata)

For the detailed flow diagram and step-by-step breakdown, see:  
[Power Automate flow overview](power-automate/flow-overview.md)

Key features:

 - Power Automate → API Gateway binary HTTP integration
 - Lambda ingestion with S3 storage and SSE encryption
 - Event-driven S3 → SFTP transfer
 - Routing rules stored in SSM (regex-based, multi-destination)
 - Streaming S3-to-SFTP (no full file load)
 - Cross-platform automation (Microsoft 365 → AWS → SFTP)

Tech stack: Power Automate, AWS API Gateway, AWS Lambda, S3, SSM Parameter Store, Python, Paramiko, SFTP
