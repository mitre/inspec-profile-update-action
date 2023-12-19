control 'SV-26513' do
  title 'System audit tool executables must not have extended ACLs.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', "Check the permissions of audit tool executables.
# ls -l /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/audispd 
If the permissions include a '+' the file has an extended ACL, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [audit file]'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-27567r1_chk'
  tag severity: 'low'
  tag gid: 'V-22373'
  tag rid: 'SV-26513r1_rule'
  tag stig_id: 'GEN002718'
  tag gtitle: 'GEN002718'
  tag fix_id: 'F-23749r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
