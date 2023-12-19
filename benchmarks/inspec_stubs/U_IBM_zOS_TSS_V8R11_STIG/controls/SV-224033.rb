control 'SV-224033' do
  title 'IBM z/OS must employ a session manager to initiate a session lock after a 15-minute period of inactivity for all connection types.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Ask the system administrator for the configuration parameters for the session manager in use.

If there is no session manager in use, this is a finding.

If the session manager is not configured to initiate a session lock after a 15-minute period of inactivity, this is a finding.'
  desc 'fix', 'Configure the session manager to initiate a session lock after a 15-minute period of inactivity.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25706r516498_chk'
  tag severity: 'medium'
  tag gid: 'V-224033'
  tag rid: 'SV-224033r877871_rule'
  tag stig_id: 'TSS0-OS-000370'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-25694r516499_fix'
  tag 'documentable'
  tag legacy: ['SV-107879', 'V-98775']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
