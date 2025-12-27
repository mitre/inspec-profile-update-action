control 'SV-218244' do
  title 'The root account must be the only account having a UID of 0.'
  desc 'If an account has a UID of 0, it has root authority.  Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account.'
  desc 'check', "Check the system for duplicate UID 0 assignments by listing all accounts assigned UID 0.

Procedure:
# awk -F: '($3 == 0) { print $1 }' /etc/passwd

If any accounts other than root are assigned UID 0, this is a finding."
  desc 'fix', 'Remove or change the UID of accounts other than root that have UID 0.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19719r554069_chk'
  tag severity: 'medium'
  tag gid: 'V-218244'
  tag rid: 'SV-218244r603259_rule'
  tag stig_id: 'GEN000880'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19717r554070_fix'
  tag 'documentable'
  tag legacy: ['V-773', 'SV-64341']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
