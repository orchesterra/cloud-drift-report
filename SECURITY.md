# Security

cloud-drift-report is read-only: it never writes to your cloud or to Terraform state, and sends nothing
anywhere except your own cloud's APIs and the Slack, Teams or webhook URLs you name with `--notify`.

To report a vulnerability, use **[Report a vulnerability](https://github.com/orchesterra/cloud-drift-report/security/advisories/new)**
(private to the maintainers). Please don't open a public issue for security problems.
