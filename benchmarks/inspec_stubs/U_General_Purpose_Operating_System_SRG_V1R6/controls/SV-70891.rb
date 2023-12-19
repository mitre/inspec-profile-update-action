control 'SV-70891' do
  title 'The operating system must retain a users session lock until that user reestablishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock shall remain in place until the user re-authenticates. No other activity aside from re-authentication shall unlock the system.'
  desc 'check', "Verify the operating system retains a user's session lock until that user reestablishes access using established identification and authentication procedures. If it does not, this is a finding."
  desc 'fix', "Configure the operating system to retain a user's session lock until that user reestablishes access using established identification and authentication procedures."
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57201r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56631'
  tag rid: 'SV-70891r1_rule'
  tag stig_id: 'SRG-OS-000028-GPOS-00009'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-61527r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
