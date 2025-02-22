control 'SV-223796' do
  title 'IBM z/OS must employ a session for users to directly initiate a session lock for all connection types.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session should the need arise for them to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Ask the system administrator for the configuration parameters for the session manager in use.

If there is no session manager in use, this is a finding.

If the session manager in use does not allow users to directly initiate a session lock for all connection types, this is a finding.'
  desc 'fix', 'Develop a procedure to offload SMF files to a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25469r515076_chk'
  tag severity: 'medium'
  tag gid: 'V-223796'
  tag rid: 'SV-223796r604139_rule'
  tag stig_id: 'RACF-OS-000420'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-25457r515077_fix'
  tag 'documentable'
  tag legacy: ['SV-107403', 'V-98299']
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
