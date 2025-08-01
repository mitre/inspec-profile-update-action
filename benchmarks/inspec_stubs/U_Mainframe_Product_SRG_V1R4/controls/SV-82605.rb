control 'SV-82605' do
  title 'The Mainframe Product must retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not want to log out because of the temporary nature of the absence. 

The session lock is implemented at the point where session activity can be determined. This is typically determined and performed at the operating system-level, but in some instances it may be at the application-level.

Regardless of where the session lock is determined and implemented, once invoked the session lock must remain in place until the user re-authenticates. No other system or application activity aside from re-authentication must unlock the system.'
  desc 'check', 'If the Mainframe Product has no data screen capability, this requirement is not applicable. 

Determine whether the Mainframe Product has the capability to retain the session lock until user reestablishes access using established Identification and authentication procedures. If it does not, this is a finding.

Examine configuration settings to determine if sessions locks are held until the user reestablishes access. If they are not properly set, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product setting to retain session locks until user reestablishes access using established identification and authentication procedures.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68673r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68115'
  tag rid: 'SV-82605r1_rule'
  tag stig_id: 'SRG-APP-000005-MFP-000005'
  tag gtitle: 'SRG-APP-000005-MFP-000005'
  tag fix_id: 'F-74231r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
