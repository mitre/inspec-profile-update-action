control 'SV-214489' do
  title 'The maximum queue length for HTTP.sys for each IIS 8.5 website must be explicitly configured.'
  desc 'In order to determine the possible causes of client connection errors and to conserve system resources, it is important to both log errors and manage those settings controlling requests to the application pool.'
  desc 'check', 'If this IIS 8.5 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Open the IIS 8.5 Manager.

Perform for each Application Pool.

Click the "Application Pools".

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "General" section and verify the value for "Queue Length" is set to 1000.

If the "Queue Length" is set to "1000" or less, this is not a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click the "Application Pools".

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "General" section and set the value for "Queue Length" to "1000" or less.

Click "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15698r766887_chk'
  tag severity: 'medium'
  tag gid: 'V-214489'
  tag rid: 'SV-214489r766889_rule'
  tag stig_id: 'IISW-SI-000256'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15696r766888_fix'
  tag 'documentable'
  tag legacy: ['SV-91571', 'V-76875']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
