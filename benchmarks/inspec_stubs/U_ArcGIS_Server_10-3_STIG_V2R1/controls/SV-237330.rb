control 'SV-237330' do
  title 'The ArcGIS Server must recognize only system-generated session identifiers.'
  desc 'Applications utilize sessions and session identifiers to control application behavior and user access. If an attacker can guess the session identifier, or can inject or manually insert session information, the session may be compromised.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement focuses on communications protection for the application session rather than for the network packet. This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'Review the ArcGIS for Server configuration to ensure the application recognizes only system generated session identifiers. Substitute the target environment’s values for [bracketed] variables.

Navigate to [https://server.domain.com/arcgis]/admin/security/config (logon when prompted.)

Verify the “User Store Configuration” value = “Type: Windows”.
If the “User Store Configuration” value is set to “Type: Built-In”, this is a finding.

Verify the “Role Store Configuration” value = “Type: Windows”.
If the “Role store Configuration” value is set to “Type: Built-In”, this is a finding.

Verify the “Authentication Tier” value is set to “WEB_ADAPTOR”.
If the “Authentication Tier” value is set to “GIS_SERVER”, this is a finding.

This test requires the account performing the check to have "Administrator" privilege to the ArcGIS for Server site. This check can be performed remotely via HTTPS. This configuration is only valid when ArcGIS for Server has been deployed onto a Windows 2008 or later operating system that is a member of an Active Directory domain that disables identifiers that show more than 35 days of inactivity.

This control is not applicable for ArcGIS Server deployments configured to allow anonymous access.

This control is not applicable for ArcGIS Server deployments which are integrated with and protected by one or more third party DoD compliant certificate authentication solutions.'
  desc 'fix', 'Configure ArcGIS for Server to ensure the application recognizes only system generated session identifiers. Substitute the target environment’s values for [bracketed] variables.

Identify a system that will serve as the service endpoint for the ArcGIS for Server environment. This must be an Active Directory joined Windows 2008 R2 system with IIS 7.5 or later installed.

If a Web Application Firewall (WAF), and/or Load Balancer serves as the user-connection endpoint, this system must be deployed on a trusted network behind these front-end technologies. On this system (locally), perform the following steps:

Install the “ArcGIS Web Adaptor”
Configure the “ArcGIS Web Adaptor” such that “Administration” is enabled via the Web Adaptor.

Enable Active Directory Client Certificate Authentication "To map client certificates by using Active Directory mapping."

Configure ArcGIS for Server to utilize Windows Users and Roles:

Navigate to ArcGIS Server Manager ([https://server.domain.com/arcgis]/manager). (logon when prompted.)
Navigate to the “Security” tab.
Navigate to the “Settings” sub-tab.
Edit “Configuration Settings” by clicking on the pencil icon.
Select “Users and roles from an existing enterprise system (LDAP or Windows Domain)”, then click “Next”.
Select “Windows Domain”, then click “Next”.
Supply Active Directory credentials with privileges “Logon To” the system on which ArcGIS for Server is deployed, then click “Next”.
Select “Web Tier” as the “Authentication Tier”, then click “Next” >> “Finish”.'
  impact 0.5
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40549r642807_chk'
  tag severity: 'medium'
  tag gid: 'V-237330'
  tag rid: 'SV-237330r879638_rule'
  tag stig_id: 'AGIS-00-000098'
  tag gtitle: 'SRG-APP-000223'
  tag fix_id: 'F-40512r642808_fix'
  tag 'documentable'
  tag legacy: ['SV-79967', 'V-65477']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
