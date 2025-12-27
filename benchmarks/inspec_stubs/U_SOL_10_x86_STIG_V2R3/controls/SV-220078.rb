control 'SV-220078' do
  title 'The root account must be the only account having an UID of 0.'
  desc 'If an account has an UID of 0, it has root authority. Multiple accounts with an UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account.'
  desc 'check', "Check the system for duplicate UID 0 assignments by listing all accounts assigned UID 0.

Procedure:
# awk -F: '$3 == 0' /etc/passwd

If any accounts other than root are assigned UID 0, this is a finding."
  desc 'fix', 'Remove or change the UID of accounts other than root that have UID 0.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21787r488342_chk'
  tag severity: 'medium'
  tag gid: 'V-220078'
  tag rid: 'SV-220078r603266_rule'
  tag stig_id: 'GEN000880'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21786r488343_fix'
  tag 'documentable'
  tag legacy: ['V-773', 'SV-39820']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
