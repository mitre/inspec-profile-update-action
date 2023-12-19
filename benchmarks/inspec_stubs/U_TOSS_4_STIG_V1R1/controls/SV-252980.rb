control 'SV-252980' do
  title 'TOSS audit logs must be owned by group root to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Verify the audit logs are owned by group root.

First, determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the location of the audit log file, check if the audit log is owned by group "root" with the following command:

$ sudo ls -l /var/log/audit/audit.log
-rw------- 1 root root 908084 Jul 19 23:10 /var/log/audit/audit.log

If the audit log is not owned by group "root", this is a finding.'
  desc 'fix', 'Configure the audit log and audit log directory to be protected from unauthorized read access, by setting the correct owner as "root" with the following command:

$ sudo chgrp root [audit_log_file]

Replace "[audit_log_file]" to the correct audit log path, by default this location is "/var/log/audit/audit.log."

Configure the audit log to be owned by root by configuring the log group in the /etc/audit/auditd.conf file:

log_group = root'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56433r824262_chk'
  tag severity: 'medium'
  tag gid: 'V-252980'
  tag rid: 'SV-252980r824264_rule'
  tag stig_id: 'TOSS-04-030150'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-56383r824263_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
