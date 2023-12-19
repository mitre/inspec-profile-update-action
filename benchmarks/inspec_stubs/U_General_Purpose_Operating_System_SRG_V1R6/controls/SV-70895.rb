control 'SV-70895' do
  title 'The operating system must provide the capability for users to directly initiate a session lock for all connection types.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session should the need arise for them to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Verify the operating system provides the capability for users to directly initiate a session lock for all connection types. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide the capability for users to directly initiate a session lock for all connection types.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57205r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56635'
  tag rid: 'SV-70895r1_rule'
  tag stig_id: 'SRG-OS-000030-GPOS-00011'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-61531r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
