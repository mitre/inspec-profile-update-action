control 'SV-254718' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) must be configured with an inactivity timeout of 15 minutes or less.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their application session prior to vacating the vicinity, applications need to be able to identify when a user's application session has idled and take action to initiate the session lock."
  desc 'check', 'Verify the BEMS inactivity timeout is set to 15 minutes or less:

1. Find the xml file "jetty.xml" located in the BEMS install directory on the BEMS host Windows server. 
2. Find the "maxIdleTime" field. (Note: "idleTimeout" may be the field, depending on the version of BEMS.)
3. Verify it is set to 900 or less (seconds). (Note: time may be in milliseconds, depending on the version of BEMS. In this case, the value would be 900000.)

If the BEMS inactivity timeout is not set to 15 minutes (900 seconds) or less, this is a finding.'
  desc 'fix', 'Configure BEMS with an inactivity timeout of 15 minutes or less.

1. Find the xml file "jetty.xml" located in the BEMS install directory on the BEMS host Windows server. 
2. Find the "maxIdleTime" field and set it to 900 or less (seconds). (Note: "idleTimeout" may be the field and time may be in milliseconds, depending on the version of BEMS. In this case, the value would be 900000.)
3. Save the file.
4. Restart the BEMS server.'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58329r870239_chk'
  tag severity: 'medium'
  tag gid: 'V-254718'
  tag rid: 'SV-254718r870239_rule'
  tag stig_id: 'BEMS-03-013700'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58275r861878_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
