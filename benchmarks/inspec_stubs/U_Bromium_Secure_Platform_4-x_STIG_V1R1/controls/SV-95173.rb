control 'SV-95173' do
  title 'The Bromium Enterprise Controller (BEC) must have the base policy Logging Level set to Debug.'
  desc 'The default policy logging level captures the maximum level of data available to the administrator for forensic purposes and troubleshooting. This is required for analyzing Indicators of Compromise (IOCs) that may necessitate an alert from the events server and action by the system administrator.'
  desc 'check', 'Inspect the base policy for all endpoints. 

1. From the management console, click on "Policies". 
2. Select the base policy.
3. Select the "Manageability" tab. 
4. Inspect the Logging level setting.

If the BEC base policy Logging level has not been set to "Debug", this is a finding.'
  desc 'fix', 'Enable the Debug Logging level.

1. From the management console, click on "Policies". 
2. Select the base policy.
3. Select the "Manageability" tab. 
4. Set the Logging level to "Debug".
5. Click "Save and Deploy".'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80141r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80469'
  tag rid: 'SV-95173r1_rule'
  tag stig_id: 'BROM-00-001135'
  tag gtitle: 'SRG-APP-000471'
  tag fix_id: 'F-87275r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
