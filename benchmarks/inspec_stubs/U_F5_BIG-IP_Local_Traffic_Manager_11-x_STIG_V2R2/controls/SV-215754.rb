control 'SV-215754' do
  title 'The BIG-IP Core implementation must be configured to protect audit tools from unauthorized deletion.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network elements providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', "Verify the BIG-IP Core is configured to protect audit information from unauthorized read access.

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Options.

Under 'Log Access', verify unauthorized roles are set to 'Deny'.

If the BIG-IP Core is not configured to protect audit information from unauthorized deletion, this is a finding."
  desc 'fix', 'Configure the BIG-IP Core to protect audit tools from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16946r291075_chk'
  tag severity: 'medium'
  tag gid: 'V-215754'
  tag rid: 'SV-215754r557356_rule'
  tag stig_id: 'F5BI-LT-000065'
  tag gtitle: 'SRG-NET-000103-ALG-000061'
  tag fix_id: 'F-16944r291076_fix'
  tag 'documentable'
  tag legacy: ['V-60289', 'SV-74719']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
