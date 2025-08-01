control 'SV-218384' do
  title 'System audit tool executables must not have extended ACLs.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', "Check the permissions of audit tool executables.
# ls -l /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/audispd 
If the permissions include a '+' the file has an extended ACL, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [audit file]'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19859r554489_chk'
  tag severity: 'low'
  tag gid: 'V-218384'
  tag rid: 'SV-218384r603259_rule'
  tag stig_id: 'GEN002718'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-19857r554490_fix'
  tag 'documentable'
  tag legacy: ['V-22373', 'SV-64097']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
