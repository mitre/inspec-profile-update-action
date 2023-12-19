control 'SV-76907' do
  title 'ColdFusion must have the WebSocket Service disabled.'
  desc 'Application servers provide a myriad of differing processes, features, and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system.  The WebSocket Service is used to develop real-time applications for stock, charting, online gaming, social networking, dashboard for various purposes, and monitoring.  The service uses http or https for communication either to a proxy server or to the built-in WebSocket Server.  When the service is enabled and not used, resources are used but set idle.  To allow the idle resources to be used for other services, if the WebSocket service is not be used by hosted applications, the service must be disabled.'
  desc 'check', 'Ask the administrator if WebSocket services are being used by any hosted applications.

If hosted applications are using the service, this is not a finding.

Within the Administrator Console, navigate to the "WebSocket" page under the "Server Settings" menu.

If "Enable WebSocket Service" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "WebSocket" page under the "Server Settings" menu.  Uncheck "Enable WebSocket Service" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63221r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62417'
  tag rid: 'SV-76907r1_rule'
  tag stig_id: 'CF11-03-000102'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-68337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
