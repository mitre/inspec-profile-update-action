control 'SV-218775' do
  title 'The application pool for each IIS 10.0 website must have a recycle time explicitly set.'
  desc 'Application pools can be periodically recycled to avoid unstable states possibly leading to application crashes, hangs, or memory leaks.'
  desc 'check', 'Note: If the IIS Application Pool is hosting Microsoft SharePoint, this is Not Applicable.

Note: If the IIS Application Pool is hosting Microsoft SharePoint, this is Not Applicable.

Note: If the IIS Application Pool is hosting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Open the IIS 10.0 Manager.

Click the “Application Pools”.

Perform the following for each Application Pool:

Highlight an Application Pool and click "Recycling" in the “Actions” pane.

In the Recycling Conditions window, verify at least one condition is checked as desired by the organization. 

If no conditions are checked, this is a finding.

Click Next.

In the Recycling Events to Log window, verify both the "Regular time interval" and "Specific time" boxes are selected.

If both the "Regular time interval" and "Specific time" options are not selected, this is a finding.

Click Cancel.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the “Application Pools”.

Perform the following for each Application Pool:

Highlight an Application Pool and click "Recycling" in the “Actions” pane.

In the Recycling Conditions window, select at least one means to recycle the Application Pool. 

Click Next.

In the Recycling Events to Log window, select both the "Regular time interval" and "Specific time" boxes. 

Click Finish.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20248r814379_chk'
  tag severity: 'medium'
  tag gid: 'V-218775'
  tag rid: 'SV-218775r814381_rule'
  tag stig_id: 'IIST-SI-000255'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20246r814380_fix'
  tag 'documentable'
  tag legacy: ['SV-109375', 'V-100271']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
