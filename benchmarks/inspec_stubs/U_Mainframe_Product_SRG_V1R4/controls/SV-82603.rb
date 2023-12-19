control 'SV-82603' do
  title 'The Mainframe Product must provide the capability for users to directly initiate a session lock.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not want to log out because of the temporary nature of the absence. 

The session lock is implemented at the point where session activity can be determined. This is typically at the operating system-level, but may be at the application-level. Rather than be forced to wait for a period of time to expire before the user session can be locked, applications need to provide users with the ability to manually invoke a session lock so users may secure their application should the need arise for them to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'If the Mainframe Product has no data screen capability, this requirement is not applicable. 

Determine whether the Mainframe Product allows users to directly initiate a session lock. If it does not this is a finding.

Examine the Mainframe Product configuration parameters and user attributes to determine whether user can initiate a session lock.

If the parameters are not properly set and/or user is not permitted, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product user’s attributes to enable ability to initiate a session lock.

Verify the external security manager permits it.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68671r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68113'
  tag rid: 'SV-82603r1_rule'
  tag stig_id: 'SRG-APP-000004-MFP-000004'
  tag gtitle: 'SRG-APP-000004-MFP-000004'
  tag fix_id: 'F-74229r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
