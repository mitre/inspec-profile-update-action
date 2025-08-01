control 'SV-251401' do
  title 'The Ivanti MobileIron Core server must initiate a session lock after a 15-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system, but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled. This is typically at the operating system level and results in a system lock, but may be at the application level where the application interface window is secured instead.

"
  desc 'check', 'Verify the session timeout is set to 15 minutes or less.

In the Admin Portal, go to Settings >> General >> Timeout. Verify the session timeout is set to 5, 10, or 15.

If the session timeout is not set to 5, 10, or 15, this is a finding.'
  desc 'fix', 'Configure the session timeout with this procedure:

In the Admin Portal, go to Settings >> General >> Timeout.

From the dropdown menu, choose a timeout value of 5, 10, or 15 minutes.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54836r806333_chk'
  tag severity: 'medium'
  tag gid: 'V-251401'
  tag rid: 'SV-251401r806335_rule'
  tag stig_id: 'IMIC-11-000300'
  tag gtitle: 'SRG-APP-000003-UEM-000003'
  tag fix_id: 'F-54789r806334_fix'
  tag satisfies: ['FMT_SMF.1.1(2) c.8 \nReference: PP-MDM-411047']
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
