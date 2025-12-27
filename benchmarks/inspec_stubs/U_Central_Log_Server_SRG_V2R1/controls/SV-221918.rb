control 'SV-221918' do
  title 'The Central Log Server must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to protect audit tools from unauthorized modification.

If the Central Log Server is not configured to protect audit tools from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to protect audit tools from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23633r420096_chk'
  tag severity: 'medium'
  tag gid: 'V-221918'
  tag rid: 'SV-221918r420098_rule'
  tag stig_id: 'SRG-APP-000122-AU-000140'
  tag gtitle: 'SRG-APP-000122'
  tag fix_id: 'F-23622r420097_fix'
  tag 'documentable'
  tag legacy: ['SV-109169', 'V-100065']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
