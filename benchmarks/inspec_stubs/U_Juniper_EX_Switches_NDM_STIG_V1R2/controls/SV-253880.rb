control 'SV-253880' do
  title 'The Juniper EX switch must be configured to automatically audit account modification.'
  desc 'Because the accounts in the network device are privileged, or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by only granting access to authorized personnel with the appropriate and necessary privileges.

Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Verify the network device automatically audits account modification actions. This requirement may be verified by demonstration, configuration review, or validated test results. This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server.

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

If account modification is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to automatically audit the modification of accounts.

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
  tag check_id: 'C-57332r843671_chk'
  tag severity: 'medium'
  tag gid: 'V-253880'
  tag rid: 'SV-253880r843673_rule'
  tag stig_id: 'JUEX-NM-000030'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-57283r843672_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
