control 'SV-248733' do
  title 'OL 8 audit logs must be owned by root to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality. 
 
Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit OL 8 activity.

'
  desc 'check', 'Verify the audit logs are owned by "root".  
 
Determine where the audit logs are stored with the following command: 
 
$ sudo grep -iw log_file /etc/audit/auditd.conf 
 
log_file = /var/log/audit/audit.log 
 
Using the location of the audit log file, determine if the audit log is owned by "root" using the following command: 
 
$ sudo ls -al /var/log/audit/audit.log 
 
rw------- 2 root root 23 Jun 11 11:56 /var/log/audit/audit.log 
 
If the audit log is not owned by "root", this is a finding.'
  desc 'fix', 'Configure the audit log to be protected from unauthorized read access by setting the correct owner as "root" with the following command: 
 
$ sudo chown root [audit_log_file] 
 
Replace "[audit_log_file]" to the correct audit log path. By default, this location is "/var/log/audit/audit.log".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52167r779763_chk'
  tag severity: 'medium'
  tag gid: 'V-248733'
  tag rid: 'SV-248733r779765_rule'
  tag stig_id: 'OL08-00-030080'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-52121r779764_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
