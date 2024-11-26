control 'SV-253917' do
  title 'The Juniper EX switch must be configured to audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Determine if the network device audits the execution of privileged functions. This requirement may be verified by demonstration, configuration review, or validated test results. 

Verify the system logs the facility "any", or minimally "change-log" and "interactive-commands", and the logging level is appropriate. Generally, the "all" (debug) logging level should be avoided because the number of logged messages is significant.

[edit system syslog]
host <IPv4 or IPv6 syslog address> {
    any info;
}
file <file name> {
    change-log info;
    interactive-commands info;
}
Note: If minimally logging only configuration changes, there will be other files receiving the events from the other logging facilities (for example "authorizations" or "firewall").

Syslog outputs in standard format unless the "structured-data" directive is configured. Verify the "structured-data" command for all files and external syslog servers requiring that format. For example:

[edit system syslog]
host <IPv4 or IPv6 syslog address> {
    change-log info;
    interactive-commands info;
    structured-data;
}
file <file name> {
    any info;
    structured-data;
}

If the network device does not audit the execution of privileged functions, this is a finding.'
  desc 'fix', 'Configure the network device to audit the execution of privileged functions.

set system syslog host <IPv4 or IPv6 syslog address> change-log info
set system syslog host <IPv4 or IPv6 syslog address> interactive-commands info
-or-
set system syslog host <IPv4 or IPv6 syslog address> any info

set system syslog file <file name> change-log info
set system syslog file <file name> interactive-commands info
-or-
set system syslog file <file name> any info'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57369r843782_chk'
  tag severity: 'medium'
  tag gid: 'V-253917'
  tag rid: 'SV-253917r843784_rule'
  tag stig_id: 'JUEX-NM-000400'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-57320r843783_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
