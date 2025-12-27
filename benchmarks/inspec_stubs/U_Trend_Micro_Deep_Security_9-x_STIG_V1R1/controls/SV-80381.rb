control 'SV-80381' do
  title 'Trend Deep Security must protect audit information from unauthorized deletion.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. 

Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. Audit information may include data from other applications or be included with the audit application itself.'
  desc 'check', %q(Review the Trend Deep Security server configuration to ensure audit information is protected from unauthorized deletion.

Interview the ISSO in order to identify  all users and their permissions to the audit records.  The ISSO must identify each user along with their assigned role configured for the appropriate information systems allowed.

Verify the information gathered against the application's, "Computer and Group Rights" for each "Role" created along with the users assigned.

If the information gathered does not match the settings within the application this is a finding.)
  desc 'fix', 'Configure the Trend Deep Security server to protect audit information from unauthorized deletion.

Edit the audit permission according the local policy by modifying the roles under:

Administration >> User Management >> Roles
Select the applicable role.
Click "Computer Rights" to modify user permissions.
Next select “Other Rights” and modify accordingly.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66539r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65891'
  tag rid: 'SV-80381r1_rule'
  tag stig_id: 'TMDS-00-000100'
  tag gtitle: 'SRG-APP-000120'
  tag fix_id: 'F-71967r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
