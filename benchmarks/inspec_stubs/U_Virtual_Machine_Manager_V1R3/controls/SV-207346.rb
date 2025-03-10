control 'SV-207346' do
  title 'The VMM must retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the VMM but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock shall remain in place until the user re-authenticates. No other activity aside from re-authentication shall unlock the VMM session.'
  desc 'check', 'Verify the VMM retains the session lock until the user reestablishes access using established identification and authentication procedures.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7603r365448_chk'
  tag severity: 'medium'
  tag gid: 'V-207346'
  tag rid: 'SV-207346r378535_rule'
  tag stig_id: 'SRG-OS-000028-VMM-000090'
  tag gtitle: 'SRG-OS-000028'
  tag fix_id: 'F-7603r365449_fix'
  tag 'documentable'
  tag legacy: ['V-56857', 'SV-71117']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
