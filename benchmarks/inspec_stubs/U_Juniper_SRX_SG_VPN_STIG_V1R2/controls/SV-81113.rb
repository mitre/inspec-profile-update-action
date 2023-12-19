control 'SV-81113' do
  title 'The Juniper SRX Services Gateway VPN must use multifactor authentication (e.g., DoD PKI) for network access to non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication uses two or more factors to achieve authentication. Use of password for user remote access for non-privileged account is not authorized.

Factors include:
(i) Something you know (e.g., password/PIN); 
(ii) Something you have (e.g., cryptographic identification device, token); or 
(iii) Something you are (e.g., biometric). 

A non-privileged account is any information system account with authorizations of a non-privileged user. 

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Ask the site to identify the VPN access profile. Verify the access profile uses LDAP, not password configuration, for user remote access to the network. Ask the site if the LDAP server used authenticates users through PKI authentication.

[edit]
show security access profile <dynamic-profile-name>

If an access profile that uses LDAP is not configured as the first option in the authentication order, this is a finding.

If password access is configured for VPN user access, this is a finding.

If the LDAP server used does not use PKI authentication, this is a finding.'
  desc 'fix', 'Configure multifactor authentication by configuring an access profile for an authentication server or services to authenticate VPN users upon logon using DoD PKI.

Example:
[edit]
set access profile dyn-vpn-ldap-xauth authentication-order ldap
set access profile dyn-vpn-ldap-xauth address-assignment pool dyn-vpn-pool
set access profile dyn-vpn-ldap-xauth ldap-options base-distinguished-name CN=Users, DC=firewall, DC=com (Location from where LDAP will start searching for users)

set access profile dyn-vpn-ldap-xauth ldap-options search search-filter sAMAccountName= 
set access profile dyn-vpn-ldap-xauth ldap-options search admin-search distinguished-name CN=Administrator, CN=Users, DC=firewall, DC=com (User who is authorized to search the ldap tree)
set access profile dyn-vpn-ldap-xauth ldap-options search admin-search password <Administrator Password>
set access profile dyn-vpn-ldap-xauth ldap-server <AD Server IP address> port 389/636 
set access firewall-authentication pass-through default-profile dyn-vpn-ldap-xauth
set access firewall-authentication web-authentication default-profile dyn-vpn-ldap-xauth

The access profile is linked to the xauth of the gateway for dynamic VPN.

set security ike gateway dyn-vpn-local-gw xauth access-profile dyn-vpn-ldap-xauth 
 
Note: Under security >> dynamic-vpn, add all the users that are going to use the dynamic VPN. The command is as follows:

set security dynamic-vpn clients all user

Note: For users who are going to use dynamic VPN, this will be the AD user logon name for each user.'
  impact 0.7
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67249r1_chk'
  tag severity: 'high'
  tag gid: 'V-66623'
  tag rid: 'SV-81113r1_rule'
  tag stig_id: 'JUSX-VN-000019'
  tag gtitle: 'SRG-NET-000140'
  tag fix_id: 'F-72699r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
