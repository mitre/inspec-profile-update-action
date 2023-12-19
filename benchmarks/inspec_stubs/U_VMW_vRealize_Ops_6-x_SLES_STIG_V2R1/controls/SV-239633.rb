control 'SV-239633' do
  title 'The SLES for vRealize audit system must be configured to audit failed attempts to access files and programs.'
  desc 'Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.'
  desc 'check', 'Verify auditd is configured to audit failed file access attempts. There must be an audit rule for each of the access syscalls logging all failed accesses (-F success=0)

# cat /etc/audit.rules /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S openat" | grep -e "-F success=0"

There must be an audit rule for each of the access syscalls logging all failed accesses (-F success=0). If not, this is a finding.'
  desc 'fix', 'Edit the audit.rules file and add the following line(s) to enable auditing of failed attempts to access files and programs:

-a exit,always -F arch=b64 -S openat -F success=0
-a exit,always -F arch=b32 -S openat -F success=0'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42866r662348_chk'
  tag severity: 'medium'
  tag gid: 'V-239633'
  tag rid: 'SV-239633r662350_rule'
  tag stig_id: 'VROM-SL-001420'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-42825r662349_fix'
  tag 'documentable'
  tag legacy: ['SV-99387', 'V-88737']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
