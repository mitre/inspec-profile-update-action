control 'SV-248737' do
  title 'The OL 8 audit log directory must have a mode of 0700 or less permissive to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality. 
 
Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit OL 8 system activity.

'
  desc 'check', 'Verify the audit log directories have a mode of "0700" or less permissive by first determining where the audit logs are stored with the following command: 
 
$ sudo grep -iw log_file /etc/audit/auditd.conf 
 
log_file = /var/log/audit/audit.log 
 
Using the location of the audit log, determine the directory where the audit logs are stored (ex: "/var/log/audit"). Run the following command to determine the permissions for the audit log folder: 
 
$ sudo stat -c "%a %n" /var/log/audit 
 
700 /var/log/audit 
 
If the audit log directory has a mode more permissive than "0700", this is a finding.'
  desc 'fix', 'Configure the audit log directory to be protected from unauthorized read access by setting the correct permissive mode with the following command: 
 
$ sudo chmod 0700 [audit_log_directory] 
 
Replace "[audit_log_directory]" to the correct audit log directory path. By default, this location is "/var/log/audit".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52171r779775_chk'
  tag severity: 'medium'
  tag gid: 'V-248737'
  tag rid: 'SV-248737r779777_rule'
  tag stig_id: 'OL08-00-030120'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-52125r779776_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
