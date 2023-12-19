control 'SV-46345' do
  title 'The maximum number of requests an application pool can process must be set.'
  desc 'IIS application pools can be periodically recycled to avoid unstable states possibly leading to application crashes, hangs, or memory leaks. By default, application pool recycling is overlapped, which means the worker process to be shut down is kept running until after a new worker process is started. After a new worker process starts, new requests are passed to it. The old worker process shuts down after it finishes processing its existing requests, or after a configured time-out, whichever comes first. This way of recycling ensures uninterrupted service to clients.'
  desc 'check', 'Note: Recycling Application Pools can create an unstable environment in a 64-bit Sharepoint environment. If operational issues arise, with supporting documentation from the ISSO this check can be downgraded to a Cat III.

1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool and click Advanced Settings in the Action Pane.
4. Scroll down to the recycling section and ensure the value for Request Limit is set to a value other than 0.  If not, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the Application Pools.
3. Highlight an Application Pool and click Advanced Settings in the Action Pane.
4. Scroll down to the recycling section and set the value for Request Limit to a value other than 0.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32854r8_chk'
  tag severity: 'medium'
  tag gid: 'V-13705'
  tag rid: 'SV-46345r3_rule'
  tag stig_id: 'WA000-WI6022 IIS7'
  tag gtitle: 'WA000-WI6022'
  tag fix_id: 'F-28989r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
