control 'SV-95191' do
  title 'The Bromium Enterprise Controller (BEC) must have Threat Intelligence lookup disabled.'
  desc 'The Enable Threat Intelligence lookup setting controls whether the controller obtains and displays threat information from Bromium Threat Intelligence, which needs an external connection to Bromium resources, which is not allowed. Optionally, the site can deploy an internal/trusted instance of the Threat Intelligence server.'
  desc 'check', 'Review the base policy to ensure that the Bromium Threat Intelligence service is disabled.

1. Using the management console, navigate to "Policies" and select the base policy. 
2. Navigate to "Security".
3. Navigate to and inspect the "Enable Bromium Threat Intelligence?" policy setting.

If the Bromium Threat Intelligence service is enabled, this is a finding.'
  desc 'fix', 'Modify the base policy to ensure that the Bromium Threat Intelligence service is disabled.

1. Using the management console, navigate to "Policies" and select the base policy. 
2. Navigate to "Security".
3. Navigate to and disable the "Enable Bromium Threat Intelligence?" policy setting.'
  impact 0.3
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80159r1_chk'
  tag severity: 'low'
  tag gid: 'V-80483'
  tag rid: 'SV-95191r1_rule'
  tag stig_id: 'BROM-00-001315'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-87293r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
