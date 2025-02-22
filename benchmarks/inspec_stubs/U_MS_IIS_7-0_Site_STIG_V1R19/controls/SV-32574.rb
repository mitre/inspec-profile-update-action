control 'SV-32574' do
  title 'An application pool’s pinging monitor must be enabled.'
  desc 'Windows Process Activation Service (WAS) manages application pool configurations and may flag a worker process as unhealthy and shut it down. An application pool’s pinging monitor must be enabled to confirm worker processes are functional. A lack of response from the worker process might mean the worker process does not have a thread to respond to the ping request, or it is hanging for some other reason. The ping interval and ping response time may need adjustment to gain access to timely information about application pool health without triggering false, unhealthy conditions; for example, instability caused by an application.'
  desc 'check', '1. Open the Internet Information Services (IIS) Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the Process Model section and ensure the value for Ping Enabled is set to True. If not, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the Process Model section and set the value for Ping Enabled to True.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32859r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13710'
  tag rid: 'SV-32574r2_rule'
  tag stig_id: 'WA000-WI6032 IIS7'
  tag gtitle: 'WA000-WI6032'
  tag fix_id: 'F-28994r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
