control 'SV-217870' do
  title 'The root account must be the only account having a UID of 0.'
  desc 'An account has root authority if it has a UID of 0. Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account. Proper configuration of sudo is recommended to afford multiple system administrators access to root privileges in an accountable manner.'
  desc 'check', "To list all password file entries for accounts with UID 0, run the following command: 

# awk -F: '($3 == 0) {print}' /etc/passwd

This should print only one line, for the user root. 
If any account other than root has a UID of 0, this is a finding."
  desc 'fix', 'If any account other than root has a UID of 0, this misconfiguration should be investigated and the accounts other than root should be removed or have their UID changed.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19351r376625_chk'
  tag severity: 'medium'
  tag gid: 'V-217870'
  tag rid: 'SV-217870r603264_rule'
  tag stig_id: 'RHEL-06-000032'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19349r376626_fix'
  tag 'documentable'
  tag legacy: ['V-38500', 'SV-50301']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
