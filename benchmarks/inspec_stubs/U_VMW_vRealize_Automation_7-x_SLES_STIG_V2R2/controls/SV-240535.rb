control 'SV-240535' do
  title 'The SLES for vRealize audit system must be configured to audit failed attempts to access files and programs.'
  desc 'Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.'
  desc 'check', 'Verify auditd is configured to audit failed file access attempts. 

# cat /etc/audit.rules /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S ftruncate" | grep -e "-F success=0"

There must be an audit rule for each of the access syscalls logging all failed accesses (-F success=0).

If not, this is a finding.'
  desc 'fix', 'Edit the audit.rules file and add the following line(s) to enable auditing of failed attempts to access files and programs:

-a exit,always -F arch=b64 -S ftruncate -F success=0
-a exit,always -F arch=b32 -S ftruncate -F success=0'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43768r671344_chk'
  tag severity: 'medium'
  tag gid: 'V-240535'
  tag rid: 'SV-240535r671346_rule'
  tag stig_id: 'VRAU-SL-001455'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-43727r671345_fix'
  tag 'documentable'
  tag legacy: ['SV-100497', 'V-89847']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
