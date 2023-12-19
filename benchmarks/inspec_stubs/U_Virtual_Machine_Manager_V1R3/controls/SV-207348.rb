control 'SV-207348' do
  title 'The VMM must provide the capability for users to directly initiate a session lock.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the VMM but does not want to log out because of the temporary nature of the absence. 

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, VMMs need to provide users with the ability to manually invoke a session lock so users may secure their session should the need arise for them to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Verify the VMM provides the capability for users to directly initiate a session lock. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to provide the capability for users to directly initiate a session lock.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7605r365454_chk'
  tag severity: 'medium'
  tag gid: 'V-207348'
  tag rid: 'SV-207348r378601_rule'
  tag stig_id: 'SRG-OS-000030-VMM-000110'
  tag gtitle: 'SRG-OS-000030'
  tag fix_id: 'F-7605r365455_fix'
  tag 'documentable'
  tag legacy: ['V-56863', 'SV-71123']
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
