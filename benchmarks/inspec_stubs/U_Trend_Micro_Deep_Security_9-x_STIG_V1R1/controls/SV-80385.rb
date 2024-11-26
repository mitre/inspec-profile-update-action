control 'SV-80385' do
  title 'Trend Deep Security must protect audit tools from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', %q(Review the Trend Deep Security server to ensure audit tools are protected from unauthorized modification.

Interview the ISSO in order to identify  all users and their permissions to the audit records.  The ISSO must identify each user along with their assigned role configured for the appropriate information systems allowed.

Verify the information gathered against the application's, "Computer and Group Rights" for each "Role" created along with the users assigned.

If the information gathered does not match the settings within the application this is a finding.)
  desc 'fix', 'Configure the Trend Deep Security server to protect audit tools from unauthorized modification.

Edit the audit permission according the local policy by modifying the roles under:

Administration >> User Management >> Roles
Select the applicable role.
Click "Computer Rights" to modify user permissions.
Next select “Other Rights” and modify accordingly.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66543r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65895'
  tag rid: 'SV-80385r1_rule'
  tag stig_id: 'TMDS-00-000110'
  tag gtitle: 'SRG-APP-000122'
  tag fix_id: 'F-71971r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
