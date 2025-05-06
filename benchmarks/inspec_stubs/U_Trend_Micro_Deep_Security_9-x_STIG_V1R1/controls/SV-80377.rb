control 'SV-80377' do
  title 'Trend Deep Security must protect audit information from any type of unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult if not impossible to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, and copy access.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', %q(Review the Trend Deep Security server configuration to ensure audit information from any type of unauthorized read access is protected.

Interview the ISSO in order to identify  all users and their permissions to the audit records.  The ISSO must identify each user along with their assigned role configured for the appropriate information systems allowed.  

Verify the information gathered against the application's, "Computer and Group Rights" for each "Role" created  along with the users assigned.

If the information gathered does not match the settings within the application this is a finding.)
  desc 'fix', 'Configure the Trend Deep Security server to protect audit information from any type of unauthorized read access.

Edit the audit permission according the local policy by modifying the roles under:

Administration >> User Management >> Roles
Select the applicable role.
Click "Computer Rights" to modify user permissions.
Next select “Other Rights” and modify accordingly.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66535r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65887'
  tag rid: 'SV-80377r1_rule'
  tag stig_id: 'TMDS-00-000090'
  tag gtitle: 'SRG-APP-000118'
  tag fix_id: 'F-71963r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
