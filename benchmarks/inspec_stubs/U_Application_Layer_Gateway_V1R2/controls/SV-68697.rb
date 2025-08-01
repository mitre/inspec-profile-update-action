control 'SV-68697' do
  title 'The ALG must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network elements providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG protects audit tools from unauthorized modification.

If the ALG does not protect audit tools from unauthorized modification, this is a finding.'
  desc 'fix', 'Configure the ALG to protect audit tools from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55067r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54451'
  tag rid: 'SV-68697r1_rule'
  tag stig_id: 'SRG-NET-000102-ALG-000060'
  tag gtitle: 'SRG-NET-000102-ALG-000060'
  tag fix_id: 'F-59305r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
