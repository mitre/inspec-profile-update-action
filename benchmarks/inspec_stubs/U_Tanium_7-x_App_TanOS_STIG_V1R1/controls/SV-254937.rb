control 'SV-254937' do
  title 'Access to the Tanium Application Servers must be restricted. Only the designated administrator(s) can have elevated privileges to the Tanium Application Servers.'
  desc 'Unauthorized software not only increases risk by increasing the number of potential vulnerabilities, it also can contain malicious code. Sending an alert (in real time) when unauthorized software is detected allows designated personnel to take action on the installation of unauthorized software.

This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., ESS and software wrappers).'
  desc 'check', "Consult with the Tanium System Administrator to review the documented list of Tanium Administrators.

1. Review the administrators' respective approved roles, as the correlated LDAP security group for the User Roles.

If the documentation does not reflect a granular, least privileged access approach to the LDAP Groups/Tanium Roles assignment, this is a finding."
  desc 'fix', %q(1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 
 
2. Click "Administration" on the top navigation banner.
 
3. Under Permissions, select "Users".

4. Analyze the users configured in the Tanium interface.

5. Determine least privileged access required for each user to perform their respective duties.

6. Move users to the appropriate LDAP security group to ensure the user is synced to the appropriate Tanium User Role.

7. If the appropriate LDAP security groups are not already configured, create the groups and add the appropriate users.

8. Ensure LDAP sync repopulates the Tanium users' associated roles accordingly.)
  impact 0.3
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58550r867709_chk'
  tag severity: 'low'
  tag gid: 'V-254937'
  tag rid: 'SV-254937r867711_rule'
  tag stig_id: 'TANS-AP-000935'
  tag gtitle: 'SRG-APP-000377'
  tag fix_id: 'F-58494r867710_fix'
  tag 'documentable'
  tag cci: ['CCI-001811']
  tag nist: ['CM-11 (1)']
end
