control 'SV-218776' do
  title 'The application pools pinging monitor for each IIS 10.0 website must be enabled.'
  desc 'Windows Process Activation Service (WAS) manages application pool configurations and may flag a worker process as unhealthy and shut it down. An application pool’s pinging monitor must be enabled to confirm worker processes are functional. A lack of response from the worker process might mean the worker process does not have a thread to respond to the ping request, or it is hanging for some other reason. The ping interval and ping response time may need adjustment to gain access to timely information about application pool health without triggering false, unhealthy conditions; for example, instability caused by an application.'
  desc 'check', 'Open the Internet Information Services (IIS) Manager.

Click "Application Pools".

Perform the following for each Application Pool:

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Process Model" section and verify the value for "Ping Enabled" is set to "True".

If the value for "Ping Enabled" is not set to "True", this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click "Application Pools".

Perform the following for each Application Pool:

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Process Model" section and set the value for "Ping Enabled" to "True".

Click "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20249r311226_chk'
  tag severity: 'medium'
  tag gid: 'V-218776'
  tag rid: 'SV-218776r558649_rule'
  tag stig_id: 'IIST-SI-000257'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20247r311227_fix'
  tag 'documentable'
  tag legacy: ['SV-109377', 'V-100273']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
