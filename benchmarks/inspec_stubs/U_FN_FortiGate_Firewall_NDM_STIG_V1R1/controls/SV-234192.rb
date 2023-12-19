control 'SV-234192' do
  title 'The FortiGate device must use LDAP for authentication.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Verify all users except admin are assigned to a remote LDAP user group.

If all administrators except admin are not configured to use remote LDAP authentication, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

Configure the LDAP server connection.

1. Go to User and Device.
2. Go to LDAP Servers and select +Create New.
3. Enter the server Name, Server IP address, or Name.
4. Enter the Common Name Identifier and Distinguished Name.
5. Set the Bind Type to Regular and enter the LDAP bind Username and Password.
6. Ensure the Secure Connection button is toggled to enable.
7. In Protocol, select LDAPS. Select certificate.
8. Click OK.

Add the LDAP server to a user group.

1. Go to User and Device.
2. Under User Groups, select +Create New.
3. Enter a Name for the group.
4. In the Remote groups section, select +Add.
5. Select the Remote Server from the dropdown list.
6. Click OK.

Then, configure the administrator account.

1. Click System.
2. Click Administrators.
3. Click +Create New and choose Administrator.
4. Specify the Username.
5. Set Type to Match a user on a remote server group.
6. In Remote User Group, select the user group that was created.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Configure the LDAP server in the CLI:
     # config user ldap
     #    edit {ldap_server_name}
     #    set server {server_ip}
     #    set cnid {cn} 
     #    set dn {dc=XYZ,dc=fortinet,dc=COM} 
     #    set type regular 
     #    set username {cn=Administrator,dc=XYA, dc=COM} 
     #    set password {bind password}
     #    set secure ldaps
     #    set ca-cert {CA certificate name}
     #   next 
     # end

3. Create a user group in the CLI:
# config user group
#    edit {Group_name}
#      set member {ldap_server_name}
#    next
# end

4. Create an administrator in the CLI:
     # config system admin
     #    edit {admin_name}
     #    set remote-auth enable
     #    set accprofile {profile name}
     #    set remote-group ldap
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37377r611763_chk'
  tag severity: 'medium'
  tag gid: 'V-234192'
  tag rid: 'SV-234192r628777_rule'
  tag stig_id: 'FGFW-ND-000165'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-37342r611764_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
