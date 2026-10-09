"""
Management command to generate a PDF scan report from the CLI.

Usage (run inside the web container):
    python manage.py generate_report --scan <domain_name_or_id> [options]

Examples:
    # Latest scan of example.com, full report, default template
    python manage.py generate_report --scan example.com

    # Specific scan ID, vulnerability-only, modern template, skip info vulns
    python manage.py generate_report --scan 42 --type vulnerability --template modern --ignore-info

    # Save to a specific output path
    python manage.py generate_report --scan example.com --output /tmp/report.pdf

Docker one-liner (run from the project root where docker-compose.yml lives):
    docker compose exec web python manage.py generate_report --scan example.com
"""

import os
import markdown

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Count, Case, When, IntegerField
from django.template.loader import get_template

from weasyprint import HTML

from reNgine.charts import (
    generate_subdomain_chart_by_http_status,
    generate_vulnerability_chart_by_severity,
)
from reNgine.common_func import get_interesting_subdomains
from scanEngine.models import VulnerabilityReportSetting
from startScan.models import ScanHistory, Subdomain, Vulnerability, IpAddress


REPORT_TYPES = ('full', 'recon', 'vulnerability')
TEMPLATES    = ('default', 'modern')


class Command(BaseCommand):
    help = (
        'Generate a PDF scan report by scan domain name or scan ID.\n'
        'Run inside the web container:\n'
        '  python manage.py generate_report --scan example.com\n'
        '  python manage.py generate_report --scan 42 --type vulnerability --template modern'
    )

    # ------------------------------------------------------------------
    # Argument definition
    # ------------------------------------------------------------------
    def add_arguments(self, parser):
        parser.add_argument(
            '--scan',
            required=False,
            default=None,
            metavar='NAME_OR_ID',
            help=(
                'Domain name (e.g. example.com) or numeric scan ID. '
                'When a domain name is given the LATEST scan for that domain is used.'
            ),
        )
        parser.add_argument(
            '--type',
            default='full',
            choices=REPORT_TYPES,
            dest='report_type',
            help='Report type: full (default), recon, or vulnerability.',
        )
        parser.add_argument(
            '--template',
            default='default',
            choices=TEMPLATES,
            dest='report_template',
            help='Report template: default (default) or modern.',
        )
        parser.add_argument(
            '--ignore-info',
            action='store_true',
            default=False,
            dest='ignore_info',
            help='Exclude informational (severity=0) vulnerabilities from the report.',
        )
        parser.add_argument(
            '--output',
            default=None,
            metavar='FILE',
            help=(
                'Output PDF file path. '
                'Defaults to <domain>_<scan_id>_<type>_report.pdf in the current directory.'
            ),
        )
        parser.add_argument(
            '--custom-report',
            action='store_true',
            default=False,
            dest='custom_report',
            help=(
                'Use the custom report template. This automatically: '
                '(1) excludes informational vulnerabilities, '
                '(2) moves Subdomains/IP tables to an Appendix, '
                '(3) filters ports 80/443 from recon findings, '
                '(4) colors vulnerability names by severity with badges.'
            ),
        )
        parser.add_argument(
            '--list',
            action='store_true',
            default=False,
            help='List available scans and exit (no PDF is generated).',
        )

    # ------------------------------------------------------------------
    # Main handler
    # ------------------------------------------------------------------
    def handle(self, *args, **options):
        # ---- list mode -----------------------------------------------
        if options['list']:
            self._list_scans()
            return

        if not options['scan']:
            raise CommandError(
                "Please provide a scan via --scan <domain_or_id>.\n"
                "Use --list to see all available scans."
            )

        # ---- resolve scan --------------------------------------------
        scan = self._resolve_scan(options['scan'])

        # ---- settings ------------------------------------------------
        report_type     = options['report_type']
        report_template = options['report_template']
        ignore_info     = options['ignore_info']
        custom_report   = options['custom_report']
        output_path     = options['output']

        # --custom-report forces ignore_info and uses the custom template
        if custom_report:
            ignore_info = True
            report_template = 'custom'
            self.stdout.write(self.style.NOTICE(
                "[*] Custom report mode: info vulns excluded, "
                "assets moved to appendix, ports 80/443 filtered, "
                "severity-colored vulnerability names."
            ))

        if output_path is None:
            safe_domain = scan.domain.name.replace('/', '_').replace(':', '_')
            suffix = '_custom' if custom_report else ''
            output_path = f"{safe_domain}_{scan.id}_{report_type}{suffix}_report.pdf"

        # ---- build report context ------------------------------------
        self.stdout.write(self.style.NOTICE(
            f"[*] Building report for scan #{scan.id}  ({scan.domain.name})"
        ))
        data = self._build_context(scan, report_type, ignore_info)

        # ---- render HTML → PDF ---------------------------------------
        self.stdout.write(self.style.NOTICE(f"[*] Rendering template: {report_template}"))
        if report_template == 'custom':
            template_name = 'report/custom.html'
        elif report_template == 'modern':
            template_name = 'report/modern.html'
        else:
            template_name = 'report/default.html'
        template = get_template(template_name)
        html_string = template.render(data)

        self.stdout.write(self.style.NOTICE("[*] Converting HTML → PDF (this may take a few seconds)…"))
        pdf_bytes = HTML(string=html_string).write_pdf()

        # ---- write output file ---------------------------------------
        with open(output_path, 'wb') as fh:
            fh.write(pdf_bytes)

        size_kb = len(pdf_bytes) // 1024
        self.stdout.write(self.style.SUCCESS(
            f"[✓] Report saved → {os.path.abspath(output_path)}  ({size_kb} KB)"
        ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _list_scans(self):
        """Print all available scans in a readable table."""
        scans = (
            ScanHistory.objects
            .select_related('domain', 'scan_type')
            .order_by('-start_scan_date')
        )
        if not scans.exists():
            self.stdout.write(self.style.WARNING("No scans found in the database."))
            return

        self.stdout.write(
            f"\n{'ID':>6}  {'Domain':<35}  {'Engine':<25}  {'Started':<20}  Status"
        )
        self.stdout.write('-' * 100)
        status_map = {-1: 'Pending', 0: 'Running', 1: 'Success', 2: 'Failed', 3: 'Aborted'}
        for s in scans:
            status  = status_map.get(s.scan_status, str(s.scan_status))
            started = s.start_scan_date.strftime('%Y-%m-%d %H:%M') if s.start_scan_date else 'N/A'
            self.stdout.write(
                f"{s.id:>6}  {s.domain.name:<35}  {s.scan_type.engine_name:<25}  {started:<20}  {status}"
            )
        self.stdout.write('')

    def _resolve_scan(self, scan_arg: str) -> ScanHistory:
        """
        Accept either a numeric scan ID or a domain name string.
        For domain names the most recent scan is returned.
        """
        # Try numeric ID first
        if scan_arg.isdigit():
            try:
                scan = ScanHistory.objects.select_related('domain', 'scan_type').get(pk=int(scan_arg))
                self.stdout.write(
                    self.style.NOTICE(f"[*] Resolved scan ID {scan_arg} → {scan.domain.name}")
                )
                return scan
            except ScanHistory.DoesNotExist:
                raise CommandError(f"No scan found with ID {scan_arg}.")

        # Treat as domain name – pick the latest scan
        scans = (
            ScanHistory.objects
            .select_related('domain', 'scan_type')
            .filter(domain__name__iexact=scan_arg)
            .order_by('-start_scan_date')
        )
        if not scans.exists():
            raise CommandError(
                f"No scan found for domain '{scan_arg}'.\n"
                f"Run with --list to see all available scans."
            )
        scan = scans.first()
        self.stdout.write(
            self.style.NOTICE(
                f"[*] Resolved '{scan_arg}' → scan ID {scan.id} "
                f"(started {scan.start_scan_date.strftime('%Y-%m-%d %H:%M')})"
            )
        )
        return scan

    def _build_context(self, scan: ScanHistory, report_type: str, ignore_info: bool) -> dict:
        """Mirror the context-building logic from startScan.views.create_report."""

        # Report type flags
        if report_type == 'recon':
            show_recon, show_vuln = True, False
            report_name = 'Reconnaissance Report'
        elif report_type == 'vulnerability':
            show_recon, show_vuln = False, True
            report_name = 'Vulnerability Report'
        else:
            show_recon, show_vuln = True, True
            report_name = 'Full Scan Report'

        # Vulnerabilities
        vuln_qs = Vulnerability.objects.filter(scan_history=scan).order_by('-severity')
        if ignore_info:
            vuln_qs = vuln_qs.exclude(severity=0)

        unique_vulns = (
            Vulnerability.objects
            .filter(scan_history=scan)
            .values('name', 'severity')
            .annotate(count=Count('name'))
            .order_by('-severity', '-count')
        )
        if ignore_info:
            unique_vulns = unique_vulns.exclude(severity=0)

        # Subdomains
        subdomains = (
            Subdomain.objects
            .filter(scan_history=scan)
            .order_by('-content_length')
        )
        subdomain_alive_count = (
            Subdomain.objects
            .filter(scan_history=scan)
            .values('name')
            .distinct()
            .filter(http_status__exact=200)
            .count()
        )

        # Sort-order annotation (mirrored from view)
        sort_annotation = Case(
            When(http_status__gte=200, http_status__lt=300, then=1),
            When(http_status__gte=300, http_status__lt=400, then=2),
            When(http_status__gte=400, http_status__lt=500, then=3),
            default=4,
            output_field=IntegerField(),
        )
        subdomains = subdomains.annotate(sort_order=sort_annotation).order_by('sort_order', 'http_status')

        interesting_subdomains = get_interesting_subdomains(scan_history=scan.id)
        interesting_subdomains = (
            interesting_subdomains
            .annotate(sort_order=sort_annotation)
            .order_by('sort_order', 'http_status')
        )

        ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains).distinct()

        # Base context
        data = {
            'scan_object':             scan,
            'unique_vulnerabilities':  unique_vulns,
            'all_vulnerabilities':     vuln_qs,
            'all_vulnerabilities_count': vuln_qs.count(),
            'subdomain_alive_count':   subdomain_alive_count,
            'interesting_subdomains':  interesting_subdomains,
            'subdomains':              subdomains,
            'ip_addresses':            ip_addresses,
            'show_recon':              show_recon,
            'show_vuln':               show_vuln,
            'report_name':             report_name,
            'is_ignore_info_vuln':     ignore_info,
            'primary_color':           '#FFB74D',
            'secondary_color':         '#212121',
        }

        # Report branding / executive summary (from VulnerabilityReportSetting)
        vuln_report_query = VulnerabilityReportSetting.objects.all()
        if vuln_report_query.exists():
            report_setting = vuln_report_query[0]
            data['company_name']           = report_setting.company_name
            data['company_address']        = report_setting.company_address
            data['company_email']          = report_setting.company_email
            data['company_website']        = report_setting.company_website
            data['show_rengine_banner']    = report_setting.show_rengine_banner
            data['show_footer']            = report_setting.show_footer
            data['footer_text']            = report_setting.footer_text
            data['show_executive_summary'] = report_setting.show_executive_summary
            data['primary_color']          = report_setting.primary_color
            data['secondary_color']        = report_setting.secondary_color

            # Substitute template variables in executive summary
            desc = report_setting.executive_summary_description
            replacements = {
                '{scan_date}':           scan.start_scan_date.strftime('%d %B, %Y'),
                '{company_name}':        report_setting.company_name,
                '{target_name}':         scan.domain.name,
                '{subdomain_count}':     str(subdomains.count()),
                '{vulnerability_count}': str(vuln_qs.count()),
                '{critical_count}':      str(vuln_qs.filter(severity=4).count()),
                '{high_count}':          str(vuln_qs.filter(severity=3).count()),
                '{medium_count}':        str(vuln_qs.filter(severity=2).count()),
                '{low_count}':           str(vuln_qs.filter(severity=1).count()),
                '{info_count}':          str(vuln_qs.filter(severity=0).count()),
                '{unknown_count}':       str(vuln_qs.filter(severity=-1).count()),
            }
            if scan.domain.description:
                replacements['{target_description}'] = scan.domain.description
            for placeholder, value in replacements.items():
                desc = desc.replace(placeholder, value)
            data['executive_summary_description'] = markdown.markdown(desc)

        # Charts
        self.stdout.write(self.style.NOTICE("[*] Generating charts…"))
        data['subdomain_http_status_chart'] = generate_subdomain_chart_by_http_status(subdomains)
        data['vulns_severity_chart'] = (
            generate_vulnerability_chart_by_severity(vuln_qs) if vuln_qs.exists() else ''
        )

        return data
