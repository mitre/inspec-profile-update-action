control 'SV-237212' do
  title 'ColdFusion must limit the maximum number of threads available for CFTHREAD.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

One way to cause a DoS for ColdFusion is to exhaust resources by using services that are not being monitored because of their nonuse by hosted applications.  One of these services is the CFTHREAD function. CFTHREAD allows a programmer to create threads of code that execute independently.  If this feature is being used, the maximum number of threads should be tuned.  If set to high, this may lead to a context-switching situation.  When this feature is not in use, the maximum number of threads must be 1.'
  desc 'check', 'Within the Administrator Console, navigate to the "Request Tuning" page under the "Server Settings" menu.  Ask the administrator if threading, calls to CFTHREAD, is being used by any of the hosted application. 

If threading is being used, this finding is not applicable.

If threading is not being used and "Maximum number of threads available for CFTHREAD" is not set to 1, this is a finding.'
  desc 'fix', 'If threading is being used, this finding is not applicable.

Navigate to the "Request Tuning page under the Server Settings" menu.  Set "Maximum number of threads available for CFTHREAD" to 1 and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40431r641729_chk'
  tag severity: 'medium'
  tag gid: 'V-237212'
  tag rid: 'SV-237212r641731_rule'
  tag stig_id: 'CF11-05-000189'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-40394r641730_fix'
  tag 'documentable'
  tag legacy: ['SV-76987', 'V-62497']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
