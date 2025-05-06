control 'SV-234278' do
  title 'The MDM server must provide the capability for users to directly initiate a session lock.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not want to log out because of the temporary nature of the absence. 

The session lock is implemented at the point where session activity can be determined. This is typically at the operating system level, but may be at the application level. Rather than be forced to wait for a period of time to expire before the user session can be locked, applications need to provide users with the ability to manually invoke a session lock so users may secure their application should the need arise for them to temporarily vacate the immediate physical vicinity. 

Satisfies:FMT_SMF.1.1(2) b 
Reference:PP-MDM-431012'
  desc 'check', 'Verify the UEM server provides the capability for users to directly initiate a session lock.

If the UEM server does not provide the capability for users to directly initiate a session lock, this is a finding.'
  desc 'fix', 'Configure the UEM server to provide the capability for users to directly initiate a session lock.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37463r613844_chk'
  tag severity: 'medium'
  tag gid: 'V-234278'
  tag rid: 'SV-234278r617355_rule'
  tag stig_id: 'SRG-APP-000004-UEM-000004'
  tag gtitle: 'SRG-APP-000004'
  tag fix_id: 'F-37428r613845_fix'
  tag 'documentable'
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
