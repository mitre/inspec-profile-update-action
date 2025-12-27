control 'SV-234256' do
  title 'The application must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system-level and results in a system lock, but may be at the application-level where the application interface window is secured instead."
  desc 'check', 'All timer values are defined in the registration table. Retrieve current value using the following command:

/opt/Citrix/VDA/bin/ctxreg,

/opt/Citrix/VDA/bin/ctxreg dump |grep MaxIdleTime

If MaxIdleTime is not set to "15 minutes" or less, this is a finding.'
  desc 'fix', 'Set value for Idle Timer
/opt/Citrix/VDA/bin/ctxreg update -k "HKLM\\System\\CurrentControlSet\\Control\\Citrix\\WinStations\\cgp" -v "MaxIdleTime" -d "0x0000000F" 
/opt/Citrix/VDA/bin/ctxreg update -k "HKLM\\System\\CurrentControlSet\\Control\\Citrix\\WinStations\\tcp" -v "MaxIdleTime" -d "0x0000000F" 
/opt/Citrix/VDA/bin/ctxreg update -k "HKLM\\System\\CurrentControlSet\\Control\\Citrix\\WinStations\\ssl" -v "MaxIdleTime" -d "0x0000000F" 
where "0x0000000F" is hexadecimal for 15'
  impact 0.5
  ref 'DPMS Target Citrix VAD 7.x LVDA'
  tag check_id: 'C-37441r612322_chk'
  tag severity: 'medium'
  tag gid: 'V-234256'
  tag rid: 'SV-234256r628796_rule'
  tag stig_id: 'LVDA-VD-000015'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-37406r612323_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
