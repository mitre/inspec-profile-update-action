control 'SV-248736' do
  title 'The OL 8 audit log directory must be group-owned by root to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality. 
 
Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit OL 8 activity.

'
  desc 'check', 'Verify the audit log directory is group-owned by "root" to prevent unauthorized read access. 
 
Determine where the audit logs are stored with the following command: 
 
$ sudo grep -iw log_file /etc/audit/auditd.conf 
 
log_file = /var/log/audit/audit.log 
 
Determine the group owner of the audit log directory by using the output of the above command (ex: "/var/log/audit/"). Run the following command with the correct audit log directory path: 
 
$ sudo ls -ld /var/log/audit 
 
drwx------ 2 root root 23 Jun 11 11:56 /var/log/audit 
 
If the audit log directory is not group-owned by "root", this is a finding.'
  desc 'fix', 'Configure the audit log to be protected from unauthorized read access by setting the correct group-owner as "root" with the following command: 
 
$ sudo chgrp root [audit_log_directory] 
 
Replace "[audit_log_directory]" with the correct audit log directory path. By default, this location is usually "/var/log/audit".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52170r779772_chk'
  tag severity: 'medium'
  tag gid: 'V-248736'
  tag rid: 'SV-248736r779774_rule'
  tag stig_id: 'OL08-00-030110'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-52124r779773_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
