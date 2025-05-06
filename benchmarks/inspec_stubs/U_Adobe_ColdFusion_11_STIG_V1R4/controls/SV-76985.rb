control 'SV-76985' do
  title 'ColdFusion must limit the maximum number of simultaneous Report threads.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

Report threads are used to process reports concurrently.  Since reporting in most applications is a process that is not time sensitive or heavily used, this setting should be minimized to minimize resource use on the application server and to minimize a method that could be used to exhaust resources by an attacker.  Unless reporting is heavily used, the number of simultaneous report threads must be set to 1.'
  desc 'check', 'Within the Administrator Console, navigate to the "Request Tuning" page under the "Server Settings" menu.

If "Maximum number of simultaneous Report threads" is not set to 1, this is a finding.'
  desc 'fix', 'Navigate to the "Request Tuning" page under the "Server Settings" menu.  Set "Maximum number of simultaneous Report threads" to 1 and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63299r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62495'
  tag rid: 'SV-76985r1_rule'
  tag stig_id: 'CF11-05-000188'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-68415r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
