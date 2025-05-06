control 'SV-214492' do
  title 'The application pools rapid fail protection settings for each IIS 8.5 website must be managed.'
  desc 'Windows Process Activation Service (WAS) manages application pool configuration and may flag a worker process as unhealthy and shut it down. The rapid fail protection must be set to a suitable value. A lack of response from the worker process might mean the worker process does not have a thread to respond to the ping request, or that it is hanging for some other reason. The ping interval and ping response time may need adjustment to gain access to timely information about application pool health without triggering false, unhealthy conditions.'
  desc 'check', 'Open the IIS 8.5 Manager.

Click the “Application Pools”.

Perform for each Application Pool.

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Rapid Fail Protection" section and verify the value for "Failure Interval" is set to "5".

If the "Failure Interval" is not set to "5" or less, this is a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click the “Application Pools”.

Perform for each Application Pool.

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Rapid Fail Protection" section and set the value for "Failure Interval" to "5" or less.

Click “OK”.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15701r310680_chk'
  tag severity: 'medium'
  tag gid: 'V-214492'
  tag rid: 'SV-214492r508659_rule'
  tag stig_id: 'IISW-SI-000259'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15699r310681_fix'
  tag 'documentable'
  tag legacy: ['SV-91577', 'V-76881']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
