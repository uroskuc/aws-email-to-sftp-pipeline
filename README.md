AWS Email-to-SFTP Pipeline

Pipeline that extracts email attachments from Office 365, sends them to AWS (API Gateway → Lambda → S3), and uses S3 events to trigger a second Lambda that delivers files to SFTP destinations.

```mermaid
flowchart LR
    %% Inbound email side
    subgraph Email_Source["Email Source"]
        O365["Office 365 / Exchange Online"]
        PA["Power Automate Flow (HTTP POST)"]
        O365 --> PA
    end

    %% AWS API entrypoint
    PA -->|"HTTP POST (file + metadata)"| APIGW["Amazon API Gateway"]

    subgraph AWS["Amazon Web Services"]
        APIGW -->|"Invoke"| L1["Lambda #1 (email_to_s3)"]

        L1 -->|"Put object"| S3["S3 Bucket (raw email files)"]

        %% Trigger from S3 to Lambda #2
        S3 -->|"S3 Put event"| L2["Lambda #2 (s3_to_sftp)"]

        %% Config-driven routing
        SSM["SSM Parameter Store (routing rules)"]
        SSM -->|"Load routes (patterns + SFTP paths)"| L2
    end

    %% SFTP destinations
    subgraph SFTP_Destinations["SFTP Destinations"]
        SFTP1["SFTP Server /caoweb/out"]
        SFTP2["SFTP Server /alpex/in"]
    end

    L2 -->|"SFTP upload (SSH)"| SFTP1
    L2 -->|"SFTP upload (SSH)"| SFTP2

```


Key capabilities:

 - Power Automate → API Gateway binary HTTP integration
 - Lambda ingestion with S3 storage and SSE encryption
 - Event-driven S3 → SFTP transfer
 - Routing rules stored in SSM (regex-based, multi-destination)
 - Streaming S3-to-SFTP (no full file load)
 - Cross-platform automation (Microsoft 365 → AWS → SFTP)

See lambda/ for AWS functions and power-automate/ for flow overview.

Tech stack: Power Automate, AWS API Gateway, AWS Lambda, S3, SSM Parameter Store, Python, Paramiko, SFTP
