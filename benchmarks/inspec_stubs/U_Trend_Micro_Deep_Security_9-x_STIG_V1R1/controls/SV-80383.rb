control 'SV-80383' do
  title 'Trend Deep Security must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', %q(Review the Trend Deep Security server configuration to ensure audit tools are protected from unauthorized access.

Interview the ISSO in order to identify all users and their permissions to the audit records.  The ISSO must identify each user along with their assigned role configured for the appropriate information systems allowed.

Verify the information gathered against the application's, "Computer and Group Rights" for each "Role" created  along with the users assigned.

If the information gathered does not match the settings within the application this is a finding.)
  desc 'fix', 'Configure the Trend Deep Security server to protect audit tools from unauthorized access.

Edit the audit permission according the local policy by modifying the roles under:

Administration >> User Management >> Roles
Select the applicable role.
Click "Computer Rights" to modify user permissions.
Next select “Other Rights” and modify accordingly.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66541r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65893'
  tag rid: 'SV-80383r1_rule'
  tag stig_id: 'TMDS-00-000105'
  tag gtitle: 'SRG-APP-000121'
  tag fix_id: 'F-71969r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
