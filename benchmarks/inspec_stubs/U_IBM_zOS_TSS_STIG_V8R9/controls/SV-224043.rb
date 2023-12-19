control 'SV-224043' do
  title 'IBM z/OS must employ a session manager for users to directly initiate a session lock for all connection types.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session should the need arise for them to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Ask the system administrator for the configuration parameters for the session manager in use.

If there is no session manager in use this is a finding.

If the session manager in use does not allow users to directly initiate a session lock for all connection types, this is a finding.'
  desc 'fix', 'Configure the session manager to allow users to directly initiate a session lock for all connection types.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25716r516528_chk'
  tag severity: 'medium'
  tag gid: 'V-224043'
  tag rid: 'SV-224043r877881_rule'
  tag stig_id: 'TSS0-OS-000480'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-25704r516529_fix'
  tag 'documentable'
  tag legacy: ['SV-107897', 'V-98793']
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
