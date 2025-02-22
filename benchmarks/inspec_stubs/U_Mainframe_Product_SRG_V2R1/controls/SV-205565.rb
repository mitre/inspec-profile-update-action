control 'SV-205565' do
  title 'The Mainframe Product  must implement organization-defined automated security responses if baseline configurations are changed in an unauthorized manner.'
  desc 'Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the system. Changes to information system configurations can have unintended side effects, some of which may be relevant to security. 

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the application. Examples of security responses include, but are not limited to, the following: halting application processing; halting selected application functions; or issuing alerts/notifications to organizational personnel when there is an unauthorized modification of a configuration item.'
  desc 'check', 'Examine Installation configuration settings.

If the Mainframe Product does not implement organization-defined automated security responses if baseline configurations are changed in an unauthorized manner, this is a finding.'
  desc 'fix', 'Configure installation and/or configuration auditing settings to implement organization-defined automated security responses if baseline configurations are changed in an unauthorized manner.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5831r299922_chk'
  tag severity: 'medium'
  tag gid: 'V-205565'
  tag rid: 'SV-205565r851330_rule'
  tag stig_id: 'SRG-APP-000379-MFP-000186'
  tag gtitle: 'SRG-APP-000379'
  tag fix_id: 'F-5831r299923_fix'
  tag 'documentable'
  tag legacy: ['SV-82797', 'V-68307']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
