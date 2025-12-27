control 'SV-218775' do
  title 'The application pool for each IIS 10.0 website must have a recycle time explicitly set.'
  desc 'Application pools can be periodically recycled to avoid unstable states possibly leading to application crashes, hangs, or memory leaks.'
  desc 'check', 'Note: If the IIS Application Pool is hosting Microsoft SharePoint, this is Not Applicable.
Note: If the IIS Application Pool is hosting Microsoft Exchange and not otherwise hosting any content, this is Not Applicable.

Open the IIS 10.0 Manager.

Expand "Application Pools".

Perform the following for each Application Pool:

Highlight an Application Pool and click "Recycling" in the "Actions" pane.

In the Recycling Conditions window, verify at least one condition is checked as desired by the organization (e.g., Regular Time Intervals, Scheduled Time).

If no conditions are checked, this is a finding.

Click "Next".

In the Recycling Events to Log window, verify at minimum the Recycling Events are selected that correspond to the conditions defined in the previous step (e.g., Regular Time Intervals, Scheduled Time).

If no events are selected, this is a finding.

Click "Cancel".'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the "Application Pools".

Perform the following for each Application Pool:

Highlight an Application Pool and click "Recycling" in the "Actions" pane.

In the Recycling Conditions window, select at least one means to recycle the Application Pool (e.g., Regular Time Intervals, Scheduled Time).

Click "Next".

In the Recycling Events to Log window, select at minimum both the events that match the conditions from the previous step (e.g., Regular Time Intervals, Scheduled Time).

Click "Finish".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20248r863018_chk'
  tag severity: 'medium'
  tag gid: 'V-218775'
  tag rid: 'SV-218775r879887_rule'
  tag stig_id: 'IIST-SI-000255'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20246r863019_fix'
  tag 'documentable'
  tag legacy: ['SV-109375', 'V-100271']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
