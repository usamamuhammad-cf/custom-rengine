# custom-rengine

reNgine is a web application reconnaissance suite. This repository contains a customized version with advanced reporting features.

## Installation

You can install and run `custom-rengine` using Docker Compose.

1. Clone the repository:
   ```bash
   git clone https://github.com/usamamuhammad-cf/custom-rengine.git
   cd custom-rengine
   ```
2. Setup environment variables by copying `.env.example` to `.env` and modifying as needed.
3. Build and run the docker containers:
   ```bash
   make build
   make up
   ```
   *(If you don't have make installed, you can use `docker compose up -d --build`)*

## Using

Once the installation is complete, access the web interface at `https://127.0.0.1`.
Login with your credentials, configure your target domains, and initiate scans.
For more details on reNgine functionality, refer to the original reNgine documentation.

## How to Generate Custom Reports

This version includes a special **Custom Template** for generating PDF reports. This custom report automatically:
- Excludes all informational vulnerabilities.
- Moves Discovered Assets (Subdomains & IPs) to a dedicated Appendix section at the end.
- Filters out ports 80 and 443 in the Reconnaissance Findings.
- Highlights vulnerabilities with color-coded severity badges.

### 1. Generating from the Web UI

1. Navigate to the **Scan History** page in the dashboard.
2. Click the Action dropdown menu (the `>` arrow) next to "View Results" for a completed scan.
3. Select **Download Report**.
4. In the pop-up modal, select **Custom Template (Filtered Ports & Assets in Appendix)** under the Report Template section.
5. Click **Download Report** to immediately save the PDF.

### 2. Generating from the CLI

You can also generate this custom report from the terminal via the `generate_report` command. Run this from your project root:
```bash
docker compose exec web python3 manage.py generate_report --scan <domain_name_or_id> --custom-report
```
The generated PDF report will be saved in the `web/` directory and can be transferred to your host machine.
