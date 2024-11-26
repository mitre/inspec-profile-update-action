control 'SV-253879' do
  title 'The Juniper EX switch must be configured to automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Review the network device configuration to determine if it automatically audits account creation or is configured to use an authentication server that would perform this function.

Verify the system logs the facility "any", or minimally "change-log" and "interactive-commands", and the logging level is appropriate. Generally, the "all" (debug) logging level should be avoided because the number of logged messages is significant.

[edit system syslog]
host <IPv4 or IPv6 syslog address> {
    any info;
}
file <file name> {
    change-log info;
    interactive-commands info;
}
Note: If minimally logging only configuration changes, there will be other files receiving the events from the other logging facilities (e.g., "authorizations" or "firewall").

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

If account creation is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to automatically audit the creation of accounts.

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
  tag check_id: 'C-57331r843668_chk'
  tag severity: 'medium'
  tag gid: 'V-253879'
  tag rid: 'SV-253879r843670_rule'
  tag stig_id: 'JUEX-NM-000020'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-57282r843669_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
