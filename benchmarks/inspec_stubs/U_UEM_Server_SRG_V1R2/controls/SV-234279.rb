control 'SV-234279' do
  title 'The MDM server must retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not want to log out because of the temporary nature of the absence. 

The session lock is implemented at the point where session activity can be determined. This is typically determined and performed at the operating system level, but in some instances it may be at the application level. 

Regardless of where the session lock is determined and implemented, once invoked the session lock must remain in place until the user re-authenticates. No other system or application activity aside from re-authentication will unlock the system. 

Satisfies:FMT_SMF.1.1(2) b 
Reference:PP-MDM-431013'
  desc 'check', 'Verify the UEM server retains the session lock until the user reestablishes access using established identification and authentication procedures.

If the UEM server does not retain the session lock until the user reestablishes access using established identification and authentication procedures, this is a finding.'
  desc 'fix', 'Configure the MDM server to retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37464r613847_chk'
  tag severity: 'medium'
  tag gid: 'V-234279'
  tag rid: 'SV-234279r879515_rule'
  tag stig_id: 'SRG-APP-000005-UEM-000005'
  tag gtitle: 'SRG-APP-000005'
  tag fix_id: 'F-37429r613848_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
