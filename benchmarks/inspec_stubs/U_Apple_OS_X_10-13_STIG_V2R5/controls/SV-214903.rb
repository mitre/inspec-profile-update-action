control 'SV-214903' do
  title 'The macOS system must be configured with the finger service disabled.'
  desc 'The "finger" service has had several security vulnerabilities in the past and is not a necessary service. It is disabled by default; enabling it would increase the attack surface of the system.'
  desc 'check', 'To check if the "finger" service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.fingerd

If the results do not show the following, this is a finding:

"com.apple.fingerd" => true'
  desc 'fix', 'To disable the "finger" service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.fingerd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16103r397281_chk'
  tag severity: 'medium'
  tag gid: 'V-214903'
  tag rid: 'SV-214903r609363_rule'
  tag stig_id: 'AOSX-13-001115'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16101r397282_fix'
  tag 'documentable'
  tag legacy: ['V-81685', 'SV-96399']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
