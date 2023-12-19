control 'SV-81159' do
  title 'The Juniper SRX Services Gateway VPN must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication and identification enables non-organizational users to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. 

This requirement only applies to components where this is specific to the function of the device or has the concept of a non-organizational user.'
  desc 'check', 'Verify that groups are not used for authentication.

[edit]
show security access profile <dynamic-profile-name>

If LDAP is not configured as the first authentication-order, this is a finding.'
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

Note: Users who are going to use dynamic VPN. This will be the AD user logon name for each user.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67295r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66669'
  tag rid: 'SV-81159r1_rule'
  tag stig_id: 'JUSX-VN-000021'
  tag gtitle: 'SRG-NET-000169'
  tag fix_id: 'F-72745r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
