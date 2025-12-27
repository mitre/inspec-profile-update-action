control 'SV-214485' do
  title 'The maximum number of requests an application pool can process for each IIS 8.5 website must be explicitly set.'
  desc 'IIS application pools can be periodically recycled to avoid unstable states possibly leading to application crashes, hangs, or memory leaks. By default, application pool recycling is overlapped, which means the worker process to be shut down is kept running until after a new worker process is started. After a new worker process starts, new requests are passed to it. The old worker process shuts down after it finishes processing its existing requests, or after a configured time-out, whichever comes first. This way of recycling ensures uninterrupted service to clients.'
  desc 'check', 'Note: If the IIS Application Pool is hosting Microsoft SharePoint, this is Not Applicable.

If this IIS 8.5 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Open the IIS 8.5 Manager.

Perform for each Application Pool.

Click "Application Pools".

Highlight an Application Pool and click "Advanced Settings" in the "Action" Pane.

Scroll down to the "Recycling section" and verify the value for "Request Limit" is set to a value other than "0".

If the "Request Limit" is set to a value of "0", this is a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click "Application Pools".

Highlight an Application Pool and click "Advanced Settings" in the "Action" Pane.

Scroll down to the "Recycling section" and set the value for "Request Limit" to greater than "0".

Click "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15694r505330_chk'
  tag severity: 'medium'
  tag gid: 'V-214485'
  tag rid: 'SV-214485r508659_rule'
  tag stig_id: 'IISW-SI-000252'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15692r505331_fix'
  tag 'documentable'
  tag legacy: ['SV-91563', 'V-76867']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
