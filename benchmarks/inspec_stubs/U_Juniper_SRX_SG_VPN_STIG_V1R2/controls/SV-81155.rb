control 'SV-81155' do
  title 'The Juniper SRX Services Gateway VPN must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following.

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 

(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN or proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'Ask the site to identify the VPN access profile. Verify the access profile uses LDAP, not password configuration, for user remote access to the network. Ask the site representative if group accounts are allowed or configured.

[edit]
show security access profile <VPN-LDAP-PROFILE-NAME>

If an access profile that uses LDAP is not configured as the first option in the authentication order, this is a finding.

If group accounts are allowed for VPN logon, this is a finding.'
  desc 'fix', 'Configure the LDAP access profile. The LDAP server must use DoD PKI for authentication of users.

[edit]
set access profile <VPN-LDAP-PROFILE-NAME> authentication-order ldap
set access profile <VPN-LDAP-PROFILE-NAME> address-assignment pool dyn-vpn-pool
set access profile <VPN-LDAP-PROFILE-NAME> ldap-options base-distinguished-name CN=Users, DC=firewall, DC=com (Location from where LDAP will start searching for users)

set access profile <VPN-LDAP-PROFILE-NAME> ldap-options search search-filter sAMAccountName= 
set access profile <VPN-LDAP-PROFILE-NAME> ldap-options search admin-search distinguished-name CN=Administrator, CN=Users, DC=firewall, DC=com (User who is authorized to search the ldap tree)
set access profile <VPN-LDAP-PROFILE-NAME> ldap-options search admin-search password <Administrator Password>
set access profile <VPN-LDAP-PROFILE-NAME> ldap-server <AD Server IP address> port 389/636 
set access firewall-authentication pass-through default-profile <VPN-LDAP-PROFILE-NAME>
set access firewall-authentication web-authentication default-profile <VPN-LDAP-PROFILE-NAME>

Note: To find the user or administrator base DN, use any LDAP browser. On an Internet search engine, search for ldp.exe, which is a very basic LDAP browser.

When using LDAP groups to authenticate a user, or a user belonging to a group in the active directory, include the following statement:

set access profile <VPN-LDAP-PROFILE-NAME> session-options client-group <group-name>

Note: Without the above statement, users are not searched based on the group name or group string.

The IP address pool configuration is as follows (the user will be assigned the IP from this pool):

set access address-assignment pool dyn-vpn-pool family inet network <IP Network for Dynamic-VPN User> (e.g.. 192.168.100.0/24)
set access address-assignment pool dyn-vpn-pool family inet range dyn-vpn-pool-range low <Starting IP address for Dynamic-VPN User> (e.g.. 192.168.100.1)
set access address-assignment pool dyn-vpn-pool family inet range dyn-vpn-pool-range high <ending IP address for Dynamic-VPN User> (e.g.. 192.168.100.100)

Note: The IP network used for dynamic VPN users should be different from the IP network of the external interface used in the IKE configuration.

The access profile is linked to the xauth of the gateway for dynamic VPN.

set security ike gateway <VPN-GATEWAY> xauth access-profile <VPN-LDAP-PROFILE-NAME> 

Under security >> dynamic-vpn, add all the users that are going to use the dynamic VPN. The command is as follows:

set security dynamic-vpn clients all user

Note: For users who are going to use dynamic VPN, this will be the AD user logon name for each user.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67291r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66665'
  tag rid: 'SV-81155r1_rule'
  tag stig_id: 'JUSX-VN-000018'
  tag gtitle: 'SRG-NET-000138'
  tag fix_id: 'F-72741r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
