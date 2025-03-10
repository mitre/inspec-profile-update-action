control 'SV-224034' do
  title 'IBM z/OS must employ a session manager to manage retaining a users session lock until that user reestablishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user re-authenticates. No other activity aside from re-authentication will unlock the system.'
  desc 'check', "Ask the system administrator for the configuration parameters for the session manager in use.

If there is no session manager in use, this is a finding.

If the session manager is not configured to retain a user's session lock until that user reestablishes access using established identification and authentication procedures, this is a finding."
  desc 'fix', 'LPA (PLPA) in the Modified LPA (MLPA) for the duration of an IPL. (The xx is the suffix designated by the MLPA parameter in the IEASYSxx member of SYS1.PARMLIB or overridden by the computer operator at IPL.)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25707r516501_chk'
  tag severity: 'medium'
  tag gid: 'V-224034'
  tag rid: 'SV-224034r877872_rule'
  tag stig_id: 'TSS0-OS-000380'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-25695r516502_fix'
  tag 'documentable'
  tag legacy: ['V-98777', 'SV-107881']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
