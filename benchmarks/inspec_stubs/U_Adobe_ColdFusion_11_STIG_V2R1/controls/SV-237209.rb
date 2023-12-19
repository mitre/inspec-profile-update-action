control 'SV-237209' do
  title 'ColdFusion must limit the maximum number of Web Service requests.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

One way to cause a DoS for ColdFusion is to exhaust resources by using services that are not being monitored because of their nonuse by hosted applications.  One of these services is Web Services.  Web Services are services that allow an application to publish SOAP web services and when being used, the number of simultaneous requests should be tuned using load testing to find the optimal value for the setting.  When not in use, this setting must be set to 1.'
  desc 'check', 'Determine if web services are being published for the hosted applications.  This may be determined by interviewing the administrator or by reviewing hosted applications code, hosted application design documentation, published web services design documentation or ColdFusion baseline documentation.

If Web Services are being published for hosted applications, this find is not applicable.

Within the Administrator Console, navigate to the "Request Tuning" page under the "Server Settings" menu.

If Web Services are not being published for hosted applications and the "Maximum number of simultaneous Web Service requests" is not set to 1, this is a finding.'
  desc 'fix', 'If Web Services are being published for hosted applications, this find is not applicable.

Navigate to the "Request Tuning" page under the "Server Settings" menu.  Set "Maximum number of simultaneous Web Service requests" to 1 and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40428r641720_chk'
  tag severity: 'medium'
  tag gid: 'V-237209'
  tag rid: 'SV-237209r641722_rule'
  tag stig_id: 'CF11-05-000186'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-40391r641721_fix'
  tag 'documentable'
  tag legacy: ['SV-76981', 'V-62491']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
