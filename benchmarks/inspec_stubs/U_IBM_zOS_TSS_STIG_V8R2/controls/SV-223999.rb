control 'SV-223999' do
  title 'IBM z/OS Session manager must properly configure wait time limits.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'If the session manager in use initiates a session lock after a 15-minute period of inactivity for all connection types, this is not a finding.'
  desc 'fix', 'Configure the session manager in use to initiate a session lock after a 15-minute period of inactivity for all connection types.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25672r516396_chk'
  tag severity: 'medium'
  tag gid: 'V-223999'
  tag rid: 'SV-223999r561402_rule'
  tag stig_id: 'TSS0-OS-000030'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-25660r516397_fix'
  tag 'documentable'
  tag legacy: ['V-98705', 'SV-107809']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
