control 'SV-80797' do
  title 'The Juniper SRX Services Gateway Firewall must be configured to support centralized management and configuration of the audit log.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The DoD requires centralized management of all network component audit record content. Network components requiring centralized audit log management must have the capability to support centralized management. The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Ensure at least one Syslog server and local files are configured to support requirements. However, the Syslog itself must also be configured to filter event records so it is not overwhelmed. A best practice when configuring the external Syslog server is to add similar log-prefixes to the log file names to help and researching of central Syslog server. Another best practice is to add a match condition to limit the recorded events to those containing the regular expression (REGEX). This requirement does not apply to audit logs generated on behalf of the device itself (management).

While the Juniper SRX inherently has the capability to generate log records, by default only the high facility levels are captured and only to local files.'
  desc 'check', 'To verify that traffic logs are being sent to the syslog server, check the syslog server files. 

If traffic logs are not being sent to the syslog server, this is a finding.'
  desc 'fix', %q(Logging for security-related sources such as screens and security policies must be configured separately. 

The following example specifies that security log messages in structured-data format (syslog format) are sent from the source <MGT IP address> (e.g., the SRX's loopback or other interface IP address) to an external syslog server.

[edit]
set security log cache
set security log format syslog
set security log source-address <MGT IP Address>
set security log stream <stream name> host <syslog server IP Address>

To get traffic logs from permitted sessions, add "then log session-close" to the policy.
To get traffic logs from denied sessions, add "then log session-init" to the policy. Enable Logging on Security Policies:

[edit]
set security policies from-zone <zone-name> to-zone <zone-name> policy <policy-name> then log <event>

Example to log session init and session close events:
set security policies from-zone trust to-zone untrust policy default-permit then log session-init
set security policies from-zone trust to-zone untrust policy default-permit then log session-close)
  impact 0.5
  ref 'DPMS Target Juniper SRX SG ALG'
  tag check_id: 'C-66953r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66307'
  tag rid: 'SV-80797r1_rule'
  tag stig_id: 'JUSX-AG-000057'
  tag gtitle: 'SRG-NET-000333-ALG-000049'
  tag fix_id: 'F-72383r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
