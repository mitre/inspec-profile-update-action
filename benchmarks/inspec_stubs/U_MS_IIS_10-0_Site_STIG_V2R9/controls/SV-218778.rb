control 'SV-218778' do
  title 'The application pools rapid fail protection settings for each IIS 10.0 website must be managed.'
  desc 'Windows Process Activation Service (WAS) manages application pool configuration and may flag a worker process as unhealthy and shut it down. The rapid fail protection must be set to a suitable value. A lack of response from the worker process might mean the worker process does not have a thread to respond to the ping request, or that it is hanging for some other reason. The ping interval and ping response time may need adjustment to gain access to timely information about application pool health without triggering false, unhealthy conditions.'
  desc 'check', 'Note: If the IIS Application Pool is hosting Microsoft SharePoint, this is Not Applicable.

If this IIS 10.0 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Open the IIS 10.0 Manager.

Click "Application Pools".

Perform the following for each Application Pool:

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Rapid Fail Protection" section and verify the value for "Failure Interval" is set to "5".

If the "Failure Interval" is not set to "5" or less, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click "Application Pools".

Perform the following for each Application Pool:

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Rapid Fail Protection" section and set the value for "Failure Interval" to "5" or less.

Click "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20251r311232_chk'
  tag severity: 'medium'
  tag gid: 'V-218778'
  tag rid: 'SV-218778r879887_rule'
  tag stig_id: 'IIST-SI-000259'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20249r311233_fix'
  tag 'documentable'
  tag legacy: ['SV-109381', 'V-100277']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
