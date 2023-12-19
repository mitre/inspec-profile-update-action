control 'SV-76975' do
  title 'ColdFusion must limit the maximum number of Flash Remoting requests.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

One way to cause a DoS for ColdFusion is to exhaust resources by using services that are not being monitored because of their nonuse by hosted applications.  One of these services is Flash Remoting.  Flash Remoting is a service that allows flash applications to interact with ColdFusion pages and, if being used, the number of simultaneous requests should be tuned using load testing to find the optimal value for the setting.  When not in use, this setting must be set to 1.'
  desc 'check', 'Within the Administrator Console, navigate to the "Request Tuning" page under the "Server Settings" menu.   Ask the administrator if flash remoting is being used  (Note: The Server Monitor feature in ColdFusion Enterprise makes use of flash remoting.).

If flash remoting is being used, this finding is not applicable.

If "Maximum number of simultaneous Flash Remoting requests" is not set to 1, this is a finding.'
  desc 'fix', 'If flash remoting is being used, this finding is not applicable.

Navigate to the "Request Tuning" page under the "Server Settings" menu.  Set "Maximum number of simultaneous Flash Remoting requests" to 1 and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63289r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62485'
  tag rid: 'SV-76975r1_rule'
  tag stig_id: 'CF11-05-000183'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-68405r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
