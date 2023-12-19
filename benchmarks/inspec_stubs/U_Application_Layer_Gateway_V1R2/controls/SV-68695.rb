control 'SV-68695' do
  title 'The ALG must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network elements providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG protects audit tools from unauthorized access.

If the ALG does not protect audit tools from unauthorized access, this is a finding.'
  desc 'fix', 'Configure the ALG to protect audit tools from unauthorized access.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55065r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54449'
  tag rid: 'SV-68695r1_rule'
  tag stig_id: 'SRG-NET-000101-ALG-000059'
  tag gtitle: 'SRG-NET-000101-ALG-000059'
  tag fix_id: 'F-59303r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
