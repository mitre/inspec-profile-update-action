control 'SV-215752' do
  title 'The BIG-IP Core implementation must be configured to protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network elements providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', "Verify the BIG-IP Core is configured to protect audit tools from unauthorized access.

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Options.

Under 'Log Access', verify unauthorized roles are set to 'Deny'.

If the BIG-IP Core is not configured to protect audit tools from unauthorized access, this is a finding."
  desc 'fix', 'Configure the BIG-IP Core to protect audit tools from unauthorized access.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16944r291069_chk'
  tag severity: 'medium'
  tag gid: 'V-215752'
  tag rid: 'SV-215752r557356_rule'
  tag stig_id: 'F5BI-LT-000061'
  tag gtitle: 'SRG-NET-000101-ALG-000059'
  tag fix_id: 'F-16942r291070_fix'
  tag 'documentable'
  tag legacy: ['V-60285', 'SV-74715']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
