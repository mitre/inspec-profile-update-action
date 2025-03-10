control 'SV-214488' do
  title 'The application pool for each IIS 8.5 website must have a recycle time explicitly set.'
  desc 'Application pools can be periodically recycled to avoid unstable states possibly leading to application crashes, hangs, or memory leaks.'
  desc 'check', 'Note: Recycling Application Pools can create an unstable environment in a 64-bit SharePoint environment. If operational issues arise, with supporting documentation from the ISSO this check can be downgraded to a Cat III.

Open the IIS 8.5 Manager.

Perform for each Application Pool.

Click the “Application Pools”.

Highlight an Application Pool and click "Advanced Settings" in the “Action” Pane.

Scroll down to the "Recycling" section and expand the "Generate Recycle Event Log Entry" section.

Verify both the "Regular time interval" and "Specific time" options are set to "True".

If both the "Regular time interval" and "Specific time" options are not set to "True", this is a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click the “Application Pools”.

Perform for each Application Pool.

Highlight an Application Pool and click "Advanced Settings" in the “Action” Pane.

Scroll down to the "Recycling" section and expand the "Generate Recycle Event Log Entry" section.

Set both the "Regular time interval" and "Specific time" options to "True".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15697r310668_chk'
  tag severity: 'medium'
  tag gid: 'V-214488'
  tag rid: 'SV-214488r508659_rule'
  tag stig_id: 'IISW-SI-000255'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15695r310669_fix'
  tag 'documentable'
  tag legacy: ['SV-91569', 'V-76873']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
