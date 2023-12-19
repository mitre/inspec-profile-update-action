control 'SV-254939' do
  title 'The application must enforce access restrictions associated with changes to application configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', "Consult with the Tanium System Administrator to review the documented list of Tanium Administrators.

1. Review the administrators' respective approved roles, as the correlated LDAP security group for the User Roles.

If the documentation does not reflect a granular, least privileged access approach to the LDAP Groups/Tanium Roles assignment, this is a finding."
  desc 'fix', %q(1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 
 
2. Click "Administration" on the top navigation banner.
 
3. Under "Permissions", select "Users".

4. Analyze the users configured in the Tanium interface.

5. Determine least privileged access required for each user to perform their respective duties.

6. Move users to the appropriate LDAP security group to ensure the user is synced to the appropriate Tanium User Role.

7. If the appropriate LDAP security groups are not already configured, create the groups and add the appropriate users.

8. Ensure LDAP sync repopulates the Tanium Users' associated Roles accordingly.)
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58552r867715_chk'
  tag severity: 'medium'
  tag gid: 'V-254939'
  tag rid: 'SV-254939r867717_rule'
  tag stig_id: 'TANS-AP-000950'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-58496r867716_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
