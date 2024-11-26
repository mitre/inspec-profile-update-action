control 'SV-252977' do
  title 'TOSS audit logs must have a mode of 0600 or less permissive to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Verify the audit logs have a mode of "0600" or less permissive.

First, determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the location of the audit log file, check if the audit log has a mode of "0600" or less permissive with the following command:

$ sudo ls -l /var/log/audit/audit.log
-rw------- 1 root root 908084 Jul 19 23:10 /var/log/audit/audit.log

If the audit log has a mode more permissive than "0600", this is a finding.'
  desc 'fix', 'Configure the audit log to be protected from unauthorized read access by setting the correct permissive mode with the following command:

$ sudo chmod 0600 [audit_log_file]

Replace "[audit_log_file]" to the correct audit log path, by default this location is "/var/log/audit/audit.log."'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56430r824253_chk'
  tag severity: 'medium'
  tag gid: 'V-252977'
  tag rid: 'SV-252977r824255_rule'
  tag stig_id: 'TOSS-04-030120'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-56380r824254_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
