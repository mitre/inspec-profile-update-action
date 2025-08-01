control 'SV-213541' do
  title 'The JBoss server must be configured to utilize syslog logging.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, access control or flow control rules invoked.

Off-loading is a common process in information systems with limited log storage capacity.

Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to off-load log records onto a different system or media than the system being logged.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.
Run the command:

Standalone configuration:
"ls /subsystem=logging/syslog-handler="

Domain configuration:
"ls /profile=<specify>/subsystem=logging/syslog-handler="
Where <specify> = the selected application server profile of; default,full, full-ha or ha.

If no values are returned, this is a finding.'
  desc 'fix', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.

Using the relevant OS commands and syntax, cd to the “<JBOSS_HOME>/bin/” folder.

Run the “jboss-cli” script.
Connect to the server and authenticate.
To add a syslog handler:
Standalone configuration: "/subsystem=logging/syslog-handler=<HANDLER_NAME:add>"
Domain configuration: "/profile=default/subsystem=logging/syslog-handler=<HANDLER_NAME:add>"

To configure a syslog handler:
Standalone configuration. "/subsystem=logging/syslog-handler=<HANDLER_NAME:write-attribute(name=ATTRIBUTE_NAME, value=ATTRIBUTE_VALUE)" Domain configuration. "/profile=default/subsystem=logging/syslog-handler=<HANDLER_NAME:write-attribute(name=ATTRIBUTE_NAME, value=ATTRIBUTE_VALUE)"

*reference the RedHat web-site for the list of syslog handler attributes and corresponding values. Sample attributes include but are not limited to: port, enabled, app-name, level, server-address, hostname, etcetera.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14764r296289_chk'
  tag severity: 'medium'
  tag gid: 'V-213541'
  tag rid: 'SV-213541r615939_rule'
  tag stig_id: 'JBOS-AS-000505'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag fix_id: 'F-14762r296290_fix'
  tag 'documentable'
  tag legacy: ['SV-76799', 'V-62309']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
