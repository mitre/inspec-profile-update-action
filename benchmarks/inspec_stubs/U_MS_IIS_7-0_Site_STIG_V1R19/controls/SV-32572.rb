control 'SV-32572' do
  title 'The Idle Timeout monitor must be enabled.'
  desc 'The idle time-out attribute controls the amount of time a worker process will remain idle before it shuts down. A worker process is idle if it is not processing requests and no new requests are received.

The purpose of this attribute is to conserve system resources; the default value for idle time-out is 20 minutes.

By default, the World Wide Web (WWW) service establishes an overlapped recycle, in which the worker process to be shut down is kept running until after a new worker process is started.'
  desc 'check', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the Process Model section and ensure the value for Idle Time out is set to 20. If not, this is a finding.

NOTE: If the site has operational reasons to set Idle Time out to an alternate value, and has supporting documentation signed by the ISSO, this is not a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool to review and click Advanced Settings in the Actions Pane.
4. Scroll down to the Process Model section and set the value for Idle Time-out to 20.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32857r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13708'
  tag rid: 'SV-32572r3_rule'
  tag stig_id: 'WA000-WI6028 IIS7'
  tag gtitle: 'WA000-WI6028'
  tag fix_id: 'F-28992r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
