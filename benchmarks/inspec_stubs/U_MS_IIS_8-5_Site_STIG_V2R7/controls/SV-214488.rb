control 'SV-214488' do
  title 'The application pool for each IIS 8.5 website must have a recycle time explicitly set.'
  desc 'Application pools can be periodically recycled to avoid unstable states possibly leading to application crashes, hangs, or memory leaks.'
  desc 'check', 'Note: Recycling Application Pools can create an unstable environment in a 64-bit SharePoint environment. If operational issues arise, with supporting documentation from the ISSO this check can be downgraded to a CAT III.

Note: If the IIS Application Pool is hosting Microsoft SharePoint, this is Not Applicable.

Note: If the IIS Application Pool is hosting Microsoft Exchange and not otherwise hosting any content, this is Not Applicable.

Open the IIS 8.5 Manager.

Click the "Application Pools".

Perform the following for each Application Pool:

Highlight an Application Pool and click "Recycling" in the "Actions" pane.

In the Recycling Conditions window, verify at least one condition is checked as desired by the organization. 

If no conditions are checked, this is a finding.

Click "Next".

In the "Recycling Events to Log" window, verify both the "Regular time interval" and "Scheduled time" boxes are selected.

If both the "Regular time interval" and "Scheduled time" options are not selected, this is a finding.

Click "Cancel".'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click the "Application Pools".

Perform the following for each Application Pool:

Highlight an Application Pool and click "Recycling" in the "Actions" pane.

In the" Recycling Conditions" window, select at least one means to recycle the Application Pool. 

Click "Next".

In the "Recycling Events to Log" windows, select both the "Regular time interval" and "Scheduled time" boxes. 

Click "Finish".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15697r881086_chk'
  tag severity: 'medium'
  tag gid: 'V-214488'
  tag rid: 'SV-214488r881088_rule'
  tag stig_id: 'IISW-SI-000255'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15695r881087_fix'
  tag 'documentable'
  tag legacy: ['SV-91569', 'V-76873']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
