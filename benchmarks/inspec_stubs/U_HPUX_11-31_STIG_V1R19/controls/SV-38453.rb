control 'SV-38453' do
  title 'The system must prevent the root account from directly logging in except from the system console.'
  desc 'Limiting the root account direct logins to only system consoles protects the root account from direct unauthorized access from a non-console device.'
  desc 'check', 'Check the /etc/securetty file contents.
# more /etc/securetty
If /etc/securetty does not exist, or has contents other than console or /dev/null, this is a finding.'
  desc 'fix', 'If the /etc/securetty file does not exist, create the file containing only the word console and ensure correct file properties.
# echo “console” > /etc/securetty'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36276r2_chk'
  tag severity: 'medium'
  tag gid: 'V-778'
  tag rid: 'SV-38453r2_rule'
  tag stig_id: 'GEN000980'
  tag gtitle: 'GEN000980'
  tag fix_id: 'F-31533r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
