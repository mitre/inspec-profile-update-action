control 'SV-207542' do
  title 'In the event of an error when validating the binding of other DNS servers identity to the BIND 9.x information, when anomalies in the operation of the signed zone transfers are discovered, for the success and failure of start and stop of the name server service or daemon, and for the success and failure of all name server events, a BIND 9.x server implementation must generate a log entry.'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being performed on the system, where an event occurred, when an event occurred, and by whom the event was triggered, in order to compile an accurate risk assessment. Logging the actions of specific events provides a means to investigate an attack, to recognize resource utilization or capacity thresholds, or to simply identify an improperly configured DNS system. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.

The DNS server should audit all failed attempts at server authentication through DNSSEC and TSIG. The actual auditing is performed by the OS/NDM but the configuration to trigger the auditing is controlled by the DNS server.

Failing to act on the validation errors may result in the use of invalid, corrupted, or compromised information. The validation of bindings can be achieved, for example, by the use of cryptographic checksums. Validations must be performed automatically.

The DNS server does not have the capability of shutting down or restarting the information system. The DNS server can be configured to generate audit records when anomalies are discovered.

'
  desc 'check', 'Verify the name server is configured to log error messages with a severity of “info”:

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
severity info;
};

If the "severity" sub statement is not set to "info", this is a finding.

Note: Setting the "severity" sub statement to "info" will log all messages for the following severity levels: Critical, Error, Warning, Notice, and Info.'
  desc 'fix', 'Edit the "named.conf" file.

Add the "severity" sub statement to the "channel" statement.

Configure the "severity" sub statement to "info"

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7797r539071_chk'
  tag severity: 'low'
  tag gid: 'V-207542'
  tag rid: 'SV-207542r612253_rule'
  tag stig_id: 'BIND-9X-001021'
  tag gtitle: 'SRG-APP-000350-DNS-000044'
  tag fix_id: 'F-7797r283681_fix'
  tag satisfies: ['SRG-APP-000350-DNS-000044', 'SRG-APP-000474-DNS-000073', 'SRG-APP-000504-DNS-000074', 'SRG-APP-000504-DNS-000082']
  tag 'documentable'
  tag legacy: ['SV-87007', 'V-72383']
  tag cci: ['CCI-000172', 'CCI-001906', 'CCI-002702', 'CCI-000366']
  tag nist: ['AU-12 c', 'AU-10 (2) (b)', 'SI-6 d', 'CM-6 b']
end
