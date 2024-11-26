control 'SV-224029' do
  title 'IBM z/OS must employ a session manager to manage retaining a users session lock until that user reestablishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock will remain in place until the user re-authenticates. No other activity aside from re-authentication will unlock the system.'
  desc 'check', "Verify the any Session Manager in use retains a user's session lock until that user reestablishes access using established identification and authentication procedures. 

If it does not, this is a finding."
  desc 'fix', "Configure any Session Manager in use to retain a user's session lock until that user reestablishes access using established identification and authentication procedures."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25702r516486_chk'
  tag severity: 'medium'
  tag gid: 'V-224029'
  tag rid: 'SV-224029r561402_rule'
  tag stig_id: 'TSS0-OS-000330'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25690r516487_fix'
  tag 'documentable'
  tag legacy: ['SV-107871', 'V-98767']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
