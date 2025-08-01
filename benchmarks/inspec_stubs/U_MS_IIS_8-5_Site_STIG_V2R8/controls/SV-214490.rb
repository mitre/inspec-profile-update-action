control 'SV-214490' do
  title 'The application pools pinging monitor for each IIS 8.5 website must be enabled.'
  desc 'Windows Process Activation Service (WAS) manages application pool configurations and may flag a worker process as unhealthy and shut it down. An application pool’s pinging monitor must be enabled to confirm worker processes are functional. A lack of response from the worker process might mean the worker process does not have a thread to respond to the ping request, or it is hanging for some other reason. The ping interval and ping response time may need adjustment to gain access to timely information about application pool health without triggering false, unhealthy conditions; for example, instability caused by an application.'
  desc 'check', 'If this IIS 8.5 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Open the Internet Information Services (IIS) Manager.

Click the "Application Pools".

Perform for each Application Pool.

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Process Model" section and verify the value for "Ping Enabled" is set to "True".

If the value for "Ping Enabled" is not set to "True", this is a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click the "Application Pools".

Perform for each Application Pool.

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Process Model" section and set the value for "Ping Enabled" to "True".

Click "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15699r766890_chk'
  tag severity: 'medium'
  tag gid: 'V-214490'
  tag rid: 'SV-214490r879887_rule'
  tag stig_id: 'IISW-SI-000257'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15697r766891_fix'
  tag 'documentable'
  tag legacy: ['SV-91573', 'V-76877']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
