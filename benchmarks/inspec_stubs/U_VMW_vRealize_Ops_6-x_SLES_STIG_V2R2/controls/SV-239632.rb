control 'SV-239632' do
  title 'The SLES for vRealize audit system must be configured to audit failed attempts to access files and programs.'
  desc 'Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.'
  desc 'check', 'Verify auditd is configured to audit failed file access attempts. There must be both an "-F exit=-EPERM" and "-F exit=-EACCES" for each access syscall:

# cat /etc/audit.rules /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S open" | grep -e "-F exit=-EPERM"

# cat /etc/audit.rules /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S open" | grep -e "-F exit=-EACCES"

There must be both an "-F exit=-EPERM" and "-F exit=-EACCES" for each access syscall. If not, this is a finding.'
  desc 'fix', 'Edit the audit.rules file and add the following line(s) to enable auditing of failed attempts to access files and programs:

-a exit,always -F arch=b64 -S open -F exit=-EPERM
-a exit,always -F arch=b64 -S open -F exit=-EACCES
-a exit,always -F arch=b32 -S open -F exit=-EPERM
-a exit,always -F arch=b32 -S open -F exit=-EACCES'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42865r662345_chk'
  tag severity: 'medium'
  tag gid: 'V-239632'
  tag rid: 'SV-239632r662347_rule'
  tag stig_id: 'VROM-SL-001415'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-42824r662346_fix'
  tag 'documentable'
  tag legacy: ['SV-99385', 'V-88735']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
