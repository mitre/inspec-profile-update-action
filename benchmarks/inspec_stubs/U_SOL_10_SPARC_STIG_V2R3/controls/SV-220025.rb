control 'SV-220025' do
  title 'The root account must be the only account having an UID of 0.'
  desc 'If an account has an UID of 0, it has root authority. Multiple accounts with an UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account.'
  desc 'check', "Check the system for duplicate UID 0 assignments by listing all accounts assigned UID 0.

Procedure:
# awk -F: '$3 == 0' /etc/passwd

If any accounts other than root are assigned UID 0, this is a finding."
  desc 'fix', 'Remove or change the UID of accounts other than root that have UID 0.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21734r482792_chk'
  tag severity: 'medium'
  tag gid: 'V-220025'
  tag rid: 'SV-220025r603265_rule'
  tag stig_id: 'GEN000880'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21733r482793_fix'
  tag 'documentable'
  tag legacy: ['SV-39820', 'V-773']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
