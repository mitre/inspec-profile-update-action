control 'SV-233060' do
  title 'The container platform must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Review the container platform to validate container platform audit tools are protected from unauthorized modification. 

If the audit tools are not protected from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the container platform to protect audit tools from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35996r600667_chk'
  tag severity: 'medium'
  tag gid: 'V-233060'
  tag rid: 'SV-233060r600669_rule'
  tag stig_id: 'SRG-APP-000122-CTR-000260'
  tag gtitle: 'SRG-APP-000122'
  tag fix_id: 'F-35964r600668_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
