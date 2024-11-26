control 'SV-217394' do
  title 'The BIG-IP appliance must be configured to protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the BIG-IP appliance protects audit tools from unauthorized access. 

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Options.

Verify authorized access is configured for each role under "Log Access".

If the BIG-IP appliance is not configured to protect its audit tools from unauthorized access, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to protect audit tools from unauthorized access.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18619r290736_chk'
  tag severity: 'medium'
  tag gid: 'V-217394'
  tag rid: 'SV-217394r557520_rule'
  tag stig_id: 'F5BI-DM-000079'
  tag gtitle: 'SRG-APP-000121-NDM-000238'
  tag fix_id: 'F-18617r290737_fix'
  tag 'documentable'
  tag legacy: ['V-60133', 'SV-74563']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
