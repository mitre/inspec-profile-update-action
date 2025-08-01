control 'SV-226597' do
  title 'System audit tool executables must not have extended ACLs.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Check the permissions of audit tool executables.
# ls -l /usr/sbin/auditd /usr/sbin/audit /usr/sbin/bsmrecord /usr/sbin/auditreduce /usr/sbin/praudit /usr/sbin/auditconfig
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [audit file]'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28758r483203_chk'
  tag severity: 'low'
  tag gid: 'V-226597'
  tag rid: 'SV-226597r603265_rule'
  tag stig_id: 'GEN002718'
  tag gtitle: 'SRG-OS-000256'
  tag fix_id: 'F-28746r483204_fix'
  tag 'documentable'
  tag legacy: ['V-22373', 'SV-26515']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
