control 'SV-221917' do
  title 'The Central Log Server must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to protect audit tools from unauthorized access.

If the Central Log Server is not configured to protect audit tools from unauthorized access, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to protect audit tools from unauthorized access.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23632r420093_chk'
  tag severity: 'medium'
  tag gid: 'V-221917'
  tag rid: 'SV-221917r420095_rule'
  tag stig_id: 'SRG-APP-000121-AU-000130'
  tag gtitle: 'SRG-APP-000121'
  tag fix_id: 'F-23621r420094_fix'
  tag 'documentable'
  tag legacy: ['SV-109167', 'V-100063']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
