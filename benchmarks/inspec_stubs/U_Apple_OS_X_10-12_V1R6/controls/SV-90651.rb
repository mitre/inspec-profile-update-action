control 'SV-90651' do
  title 'The OS X system must enforce requirements for remote connections to the information system.'
  desc 'The Screen Sharing feature allows remote users to view or control the desktop of the current user. A malicious user can take advantage of screen sharing to gain full access to the system remotely, either with stolen credentials or by guessing the username and password. Disabling Screen Sharing mitigates this risk.'
  desc 'check', 'To check if the Screen Sharing service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.screensharing

If the results do not show the following, this is a finding:

"com.apple.screensharing" => true'
  desc 'fix', 'To disable the Screen Sharing service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.screensharing

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75647r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75963'
  tag rid: 'SV-90651r1_rule'
  tag stig_id: 'AOSX-12-000055'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82601r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
