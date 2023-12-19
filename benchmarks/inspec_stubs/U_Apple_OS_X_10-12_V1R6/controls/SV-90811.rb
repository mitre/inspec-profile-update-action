control 'SV-90811' do
  title 'The OS X system must be configured with the finger service disabled.'
  desc 'The "finger" service has had several security vulnerabilities in the past and is not a necessary service. It is disabled by default; enabling it would increase the attack surface of the system.'
  desc 'check', 'To check if the "finger" service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.fingerd

If the results do not show the following, this is a finding:

"com.apple.fingerd" => true'
  desc 'fix', 'To disable the "finger" service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.fingerd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76123'
  tag rid: 'SV-90811r1_rule'
  tag stig_id: 'AOSX-12-001115'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82761r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
