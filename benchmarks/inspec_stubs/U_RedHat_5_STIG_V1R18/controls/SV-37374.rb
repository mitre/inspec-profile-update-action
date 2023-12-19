control 'SV-37374' do
  title 'The system must prevent the root account from directly logging in except from the system console.'
  desc 'Limiting the root account direct logins to only system consoles protects the root account from direct unauthorized access from a non-console device.'
  desc 'check', 'Check /etc/securetty
# more /etc/securetty
If the file does not exist, or contains more than "console" or a single "tty" device this is a finding.'
  desc 'fix', 'Create if needed and set the contents of /etc/securetty to a "console" or "tty" device.
# echo console > /etc/securetty
or
# echo tty1 > /etc/securetty'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36060r1_chk'
  tag severity: 'medium'
  tag gid: 'V-778'
  tag rid: 'SV-37374r1_rule'
  tag stig_id: 'GEN000980'
  tag gtitle: 'GEN000980'
  tag fix_id: 'F-31305r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
