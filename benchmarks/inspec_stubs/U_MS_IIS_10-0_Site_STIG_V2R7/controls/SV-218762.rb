control 'SV-218762' do
  title 'The Idle Time-out monitor for each IIS 10.0 website must be enabled.'
  desc 'The idle time-out attribute controls the amount of time a worker process will remain idle before it shuts down. A worker process is idle if it is not processing requests and no new requests are received.

The purpose of this attribute is to conserve system resources; the default value for idle time-out is 20 minutes.

By default, the World Wide Web (WWW) service establishes an overlapped recycle, in which the worker process to be shut down is kept running until after a new worker process is started.'
  desc 'check', 'If this IIS 10.0 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.
Click the Application Pools.
Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.
Scroll down to the "Process Model" section and verify the value for "Idle Time-out" is not "0".

If the "Idle Time-out" is set to "0", this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the Application Pools.

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Process Model" section and set the value for "Idle Time-out" to something other than "0". "20" or less is recommended if the amount of RAM on the system is limited.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20235r766902_chk'
  tag severity: 'medium'
  tag gid: 'V-218762'
  tag rid: 'SV-218762r850585_rule'
  tag stig_id: 'IIST-SI-000235'
  tag gtitle: 'SRG-APP-000295-WSR-000012'
  tag fix_id: 'F-20233r311185_fix'
  tag 'documentable'
  tag legacy: ['SV-109349', 'V-100245']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
