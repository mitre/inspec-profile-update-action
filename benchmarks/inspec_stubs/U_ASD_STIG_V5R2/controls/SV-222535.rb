control 'SV-222535' do
  title 'The application must disable device identifiers after 35 days of inactivity unless a cryptographic certificate is used for authentication.'
  desc 'Device identifiers are used to identify hardware devices that interact with the application much like a user account is used to identify an application user.  Examples of hardware devices include but are not limited to mobile phones, application gateways or other types of smart hardware.  

This requirement does not apply to individual application user accounts.  

This requirement is not applicable to shared information system accounts, application groups, roles (e.g., guest and anonymous accounts) that are used by the application itself in order to function.  Care must be taken to not disable identifiers that are used by the application in order to function.

Inactive device identifiers pose a risk to systems and applications. Attackers that are able to exploit an inactive identifier can potentially obtain and maintain undetected access to the application. 

Applications need to track periods of device inactivity and disable the device identifier after 35 days of inactivity.  This is usually accomplished by disabling the account used by the device to access the application.

Applications that utilize cryptographic certificates for device authentication may use the expiration date assigned to the certificate to meet this requirement with the understanding that the certificate is created and managed in accordance with DoD PKI policy and can be revoked by a trusted CA.

To avoid having to build complex device management capabilities directly into their application, developers should leverage the underlying OS or other account management infrastructure (AD, LDAP) that is already in place within the organization and meets organizational user account management requirements.

Applications are encouraged to utilize a centralized data store such as Active Directory or LDAP to offload device management requirements and ensure compliance with policy requirements.'
  desc 'check', 'Review the application documentation and interview the application administrator.

If the application is not designed to authenticate devices (such as mobile phones, gateways or other smart devices), or uses DoD PKI certificates to authenticate these devices, this requirement is NA.

Access the user management interface for the application.

Identify application device IDs.

If the application utilizes approved certificates or a centralized authentication store (Active Directory or LDAP) as the authoritative source for application authentication, and the authentication store is configured to meet the requirement to disable device IDs after 35 days of inactivity, this is not a finding.

Accounts such as guest and anonymous as well as roles and groups or other identities used to operate the application or to provide limited guest access are not applicable.

Access the application user management interface and review the account settings that pertain to devices.

Verify the application is configured to disable device accounts that have not been active or logged into the application for the past 35 days.

If the application does not disable accounts used to authenticate devices after 35 days of inactivity, this is a finding.'
  desc 'fix', 'Configure the application to disable device accounts after 35 days of inactivity or to utilize DoD PKI certificates that provide an expiration date.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24205r493513_chk'
  tag severity: 'medium'
  tag gid: 'V-222535'
  tag rid: 'SV-222535r508029_rule'
  tag stig_id: 'APSC-DV-001670'
  tag gtitle: 'SRG-APP-000163'
  tag fix_id: 'F-24194r493514_fix'
  tag 'documentable'
  tag legacy: ['V-69553', 'SV-84175']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
