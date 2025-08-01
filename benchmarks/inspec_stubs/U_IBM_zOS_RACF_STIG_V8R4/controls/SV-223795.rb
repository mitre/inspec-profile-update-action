control 'SV-223795' do
  title 'IBM z/OS must employ a session manager to manage session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock."
  desc 'check', 'Ask the system administrator for the configuration parameters for the session manager in use.

If there is no session manager in use, this is a finding.

If the session manager is not configured to initiate session lock after a 15-minute period of inactivity, this is a finding.'
  desc 'fix', 'Configure the session manager to initiate a session lock after a 15-minute period of inactivity.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25468r515073_chk'
  tag severity: 'medium'
  tag gid: 'V-223795'
  tag rid: 'SV-223795r604139_rule'
  tag stig_id: 'RACF-OS-000410'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-25456r515074_fix'
  tag 'documentable'
  tag legacy: ['V-98297', 'SV-107401']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
