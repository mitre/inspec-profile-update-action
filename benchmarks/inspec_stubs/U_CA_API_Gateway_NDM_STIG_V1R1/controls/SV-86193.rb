control 'SV-86193' do
  title 'The CA API Gateway must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify by confirming the following lines are part of "rsyslogd.conf":

# auditd audit.log
$ModLoad imfile
$InputFileName /var/log/audit/audit.log
$InputFileTag tag_audit_log:
$InputFileStateFile audit_log
$InputFileSeverity info
$InputFileFacility local6
$InputRunFileMonitor

Further verify that this line is also part of the rsyslogd.conf file:
local6.* @@loghost.ca.com

If "rsyslogd.conf" does not contain the above lines, this is a finding.'
  desc 'fix', 'Setup steps:

Configure rsyslogd to monitor "/var/log/auditd/auditd.log" file for updates by adding stanza:

# auditd audit.log
$ModLoad imfile
$InputFileName /var/log/audit/audit.log
$InputFileTag tag_audit_log:
$InputFileStateFile audit_log
$InputFileSeverity info
$InputFileFacility local6
$InputRunFileMonitor

to the "/etc/rsyslogd.conf" file. 

Note: This creates audit log entries for facility "local6" and priority "info." This can be changed to suite.

Configure "rsyslogd" to forward this combination (local6.info) to the appropriate loghost by adding logging rule to the rule section of the "rsyslogd.conf" file:

local6.* @@loghost.ca.com

Note that the syntax "@@loghost.ca.com" means that the records are forwarded via TCP.

A single "@" before the remote loghost would mean the records are forwarded via UDP.'
  impact 0.3
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71947r1_chk'
  tag severity: 'low'
  tag gid: 'V-71569'
  tag rid: 'SV-86193r1_rule'
  tag stig_id: 'CAGW-DM-000350'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-77893r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
