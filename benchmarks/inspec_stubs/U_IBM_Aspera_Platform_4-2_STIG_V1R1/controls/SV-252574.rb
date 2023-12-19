control 'SV-252574' do
  title 'The IBM Aspera Console feature audit tools must be protected from unauthorized modification or deletion.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network elements providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

This does not apply to audit logs generated on behalf of the device itself (management).

'
  desc 'check', 'Verify the world ownership of subdirectories within the /opt/aspera/console directory. Only the "public" subdirectory should have any access outside of the owner or group.

sudo find /opt/aspera/console -perm -0002 -exec ls -lLd {} \\;

If any files or directories have world write permissions, this is a finding.'
  desc 'fix', 'Remove the ability for world to write to any file that has been modified to world writeable. 

$ sudo chmod o-w <placefilenamehere>'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56030r817890_chk'
  tag severity: 'medium'
  tag gid: 'V-252574'
  tag rid: 'SV-252574r817892_rule'
  tag stig_id: 'ASP4-CS-040270'
  tag gtitle: 'SRG-NET-000102-ALG-000060'
  tag fix_id: 'F-55980r817891_fix'
  tag satisfies: ['SRG-NET-000102-ALG-000060', 'SRG-NET-000103-ALG-000061']
  tag 'documentable'
  tag cci: ['CCI-001494', 'CCI-001495']
  tag nist: ['AU-9', 'AU-9']
end
