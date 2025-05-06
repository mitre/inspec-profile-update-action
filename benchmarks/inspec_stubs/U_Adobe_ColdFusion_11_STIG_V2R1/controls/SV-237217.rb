control 'SV-237217' do
  title 'ColdFusion must limit the maximum number of POST requests parameters.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

Limiting the number of POST requests to the maximum number of form fields on any given page within the hosted application is used to mitigate the DoS attack known as HashDOS.  

ColdFusion provides the postParameterLimit setting to address this risk.  This is a tunable parameter that should be set as low as the application and the hardware will allow.  

If the system administrator has not documented and identified the specific setting value based on their specific application and system tuning requirements, this parameter must be set to "50" or less.'
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

Review system documentation. Determine if the "Maximum number of POST request parameters" setting has been tuned to account for application and system performance.

If "Maximum number of POST request parameters" is not set to "50" or is not set in accordance with documented tuning parameters, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Set "Maximum number of POST request parameters" to "50" or to the value specified in the documented tuning parameters and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40436r641744_chk'
  tag severity: 'medium'
  tag gid: 'V-237217'
  tag rid: 'SV-237217r641746_rule'
  tag stig_id: 'CF11-05-000194'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-40399r641745_fix'
  tag 'documentable'
  tag legacy: ['SV-76997', 'V-62507']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
