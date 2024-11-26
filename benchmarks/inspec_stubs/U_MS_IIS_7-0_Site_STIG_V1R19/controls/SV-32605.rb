control 'SV-32605' do
  title 'An application pool’s rapid fail protection settings must be managed.'
  desc 'Windows Process Activation Service (WAS) manages application pool configuration and may flag a worker process as unhealthy and shut it down.  The rapid fail protection must be set to a suitable value.  A lack of response from the worker process might mean the worker process does not have a thread to respond to the ping request, or that it is hanging for some other reason. The ping interval and ping response time may need adjustment to gain access to timely information about application pool health without triggering false, unhealthy conditions.'
  desc 'check', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the Rapid Fail Protection section and ensure the value for Failure Interval is set to 5. If not, this is a finding.

NOTE: If the site has operational reasons to set Failure Interval to an alternate value, and has supporting documentation signed by the ISSO, this is not a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the Rapid Fail Protection section and set the value for Failure Interval to 5.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32865r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13712'
  tag rid: 'SV-32605r3_rule'
  tag stig_id: 'WA000-WI6036 IIS7'
  tag gtitle: 'WA000-WI6036'
  tag fix_id: 'F-29009r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
