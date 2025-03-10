control 'SV-218378' do
  title 'System audit logs must be group-owned by root, bin, sys, or system.'
  desc 'Sensitive system and user information could provide a malicious user with enough information to penetrate further into the system.'
  desc 'check', 'Check the group ownership of the audit logs.

Procedure:
# grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %G:%n

If any audit log file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of the audit log file(s).

Procedure:
# chgrp root <audit log file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19853r554471_chk'
  tag severity: 'medium'
  tag gid: 'V-218378'
  tag rid: 'SV-218378r603259_rule'
  tag stig_id: 'GEN002690'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-19851r554472_fix'
  tag 'documentable'
  tag legacy: ['V-22702', 'SV-63873']
  tag cci: ['CCI-000162', 'CCI-000163']
  tag nist: ['AU-9 a', 'AU-9 a']
end
