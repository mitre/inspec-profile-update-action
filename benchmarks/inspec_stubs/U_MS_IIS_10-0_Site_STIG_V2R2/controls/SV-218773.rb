control 'SV-218773' do
  title 'The amount of virtual memory an application pool uses for each IIS 10.0 website must be explicitly set.'
  desc 'IIS application pools can be periodically recycled to avoid unstable states possibly leading to application crashes, hangs, or memory leaks. By default, application pool recycling is overlapped, which means the worker process to be shut down is kept running until after a new worker process is started. After a new worker process starts, new requests are passed to it. The old worker process shuts down after it finishes processing its existing requests, or after a configured time-out, whichever comes first. This way of recycling ensures uninterrupted service to clients.'
  desc 'check', 'Note: If the IIS Application Pool is hosting Microsoft SharePoint, this is Not Applicable.

If this IIS 10.0 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Open the IIS 10.0 Manager.

Perform the following for each Application Pool:

Click "Application Pools".

Highlight an Application Pool and click "Advanced Settings" in the Action Pane.

In the "Advanced Settings" dialog box scroll down to the "Recycling" section and verify the value for "Virtual Memory Limit" is not set to "0".

If the value for "Virtual Memory Limit" is set to "0", this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click “Application Pools”.

Perform the following for each Application Pool:

Highlight an Application Pool and click "Advanced Settings" in the "Action" Pane.

In the "Advanced Settings" dialog box scroll down to the "Recycling" section and set the value for "Virtual Memory Limit" to a value other than "0".

Click "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20246r311217_chk'
  tag severity: 'medium'
  tag gid: 'V-218773'
  tag rid: 'SV-218773r558649_rule'
  tag stig_id: 'IIST-SI-000253'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-20244r311218_fix'
  tag 'documentable'
  tag legacy: ['SV-109371', 'V-100267']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
