control 'SV-222658' do
  title 'All products must be supported by the vendor or the development team.'
  desc 'Unsupported commercial and government developed software products should not be used because fixes to newly identified bugs will not be implemented by the vendor or development team. The lack of security updates can result in potential vulnerabilities.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify all software components.

Review the version information and identify the vendor if COTS software.

Access the vendor website to verify the version is still supported.

Ask the application representative for proof that the application and all of its components are supported.

Examples of proof may include:

design documentation that includes support information, support specific contract documentation, successful creation of vendor support tickets, website toll free support phone numbers etcetera.

If any of the software components are not supported by a COTS vendor or a GOTS organization, this is a finding.'
  desc 'fix', 'Remove or decommission all unsupported software products in the application.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24328r493882_chk'
  tag severity: 'high'
  tag gid: 'V-222658'
  tag rid: 'SV-222658r879887_rule'
  tag stig_id: 'APSC-DV-003240'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24317r493883_fix'
  tag 'documentable'
  tag legacy: ['SV-85017', 'V-70395']
  tag cci: ['CCI-003376']
  tag nist: ['SA-22 a']
end
