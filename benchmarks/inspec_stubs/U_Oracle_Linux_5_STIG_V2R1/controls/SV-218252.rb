control 'SV-218252' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19727r554093_chk'
  tag severity: 'medium'
  tag gid: 'V-218252'
  tag rid: 'SV-218252r603259_rule'
  tag stig_id: 'GEN000980'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-19725r554094_fix'
  tag 'documentable'
  tag legacy: ['V-778', 'SV-64389']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
