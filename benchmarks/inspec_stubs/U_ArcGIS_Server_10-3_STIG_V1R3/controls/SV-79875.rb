control 'SV-79875' do
  title 'The ArcGIS Server must use Windows authentication to enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions.

'
  desc 'check', 'Review the ArcGIS for Server configuration to ensure that the application enforces approved authorizations for logical access to information system resources.

Substitute the target environment’s values for [bracketed] variables.

Navigate to [https://server.domain.com/arcgis]/admin/security/config (logon when prompted.)

Verify the "User Store Configuration" value = "Type: Windows".
If the "User Store Configuration" value is set to "Type: Built-In", this is a finding.

Verify the "Role Store Configuration" value = "Type: Windows".

If the "Role store Configuration" value is set to "Type: Built-In", this is a finding.

Verify the "Authentication Tier" value is set to "WEB_ADAPTOR".
If the "Authentication Tier" value is set to "GIS_SERVER", this is a finding.

Open IIS Manager on the system that hosts the ArcGIS Web Adaptor.
Select the "[arcgis]" application.
Open "SSL Settings".
Verify the "Client Certificates" property is set to "Require".

If the "Client Certificates" property is not set to "Require", this is a finding.

This test requires the account performing the check to have "Administrator" privilege to the ArcGIS for Server site. This check can be performed remotely via HTTPS. This configuration is only valid when ArcGIS for Server has been deployed onto a Windows 2008 or later operating system that is a member of an Active Directory domain.

This control is not applicable for ArcGIS Server deployments configured to allow anonymous access.

This control is not applicable for ArcGIS Server deployments which are integrated with and protected by one or more third party DoD-compliant certificate authentication solutions.'
  desc 'fix', %q(Configure ArcGIS for Server to ensure that the application enforces approved authorizations for logical access to information system resources.  Substitute the target environment’s values for [bracketed] variables.

Identify a system that will serve as the service endpoint for the ArcGIS for Server environment. This must be an Active Directory joined Windows 2008 R2 system with IIS 7.5 or later installed. If a Web Application Firewall (WAF), and/or Load Balancer serves as the user-connection endpoint, this system must be deployed on a trusted network behind these front-end technologies. On this system (locally), perform the following steps:

Install the “ArcGIS Web Adaptor”.'
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

Select “Web Tier” as the “Authentication Tier”, then click “Next” >> “Finish”.

On the system that hosts the ArcGIS Web Adaptor, open IIS Manager.

Select “[arcgis]” application >> SSL Settings >> Check “Require SSL” and “Require Client Certificates” >> Apply.)
  impact 0.7
  ref 'DPMS Target ArcGIS 10.3'
  tag check_id: 'C-65963r3_chk'
  tag severity: 'high'
  tag gid: 'V-65385'
  tag rid: 'SV-79875r2_rule'
  tag stig_id: 'AGIS-00-000016'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-71327r4_fix'
  tag satisfies: ['SRG-APP-000033', 'SRG-APP-000038', 'SRG-APP-000080', 'SRG-APP-000148', 'SRG-APP-000149', 'SRG-APP-000150', 'SRG-APP-000151', 'SRG-APP-000152', 'SRG-APP-000153', 'SRG-APP-000158', 'SRG-APP-000163', 'SRG-APP-000172', 'SRG-APP-000176', 'SRG-APP-000177', 'SRG-APP-000178', 'SRG-APP-000180', 'SRG-APP-000190', 'SRG-APP-000220']
  tag 'documentable'
  tag cci: ['CCI-000166', 'CCI-000186', 'CCI-000187', 'CCI-000197', 'CCI-000206', 'CCI-000213', 'CCI-000764', 'CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-000770', 'CCI-000778', 'CCI-000795', 'CCI-000804', 'CCI-001133', 'CCI-001185', 'CCI-001368']
  tag nist: ['AU-10', 'IA-5 (2) (a) (1)', 'IA-5 (2) (a) (2)', 'IA-5 (1) (c)', 'IA-6', 'AC-3', 'IA-2', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (5)', 'IA-3', 'IA-4 e', 'IA-8', 'SC-10', 'SC-23 (1)', 'AC-4']
end
