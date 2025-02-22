control 'SV-237321' do
  title 'The ArcGIS Server must use Windows authentication for supporting account management functions.'
  desc "Enterprise environments make application account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. 

A comprehensive application account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended or terminated or by disabling accounts located in non-centralized account stores such as multiple servers. This requirement applies to all account types, including individual/user, shared, group, system, guest/anonymous, emergency, developer/manufacturer/vendor, temporary, and service.

The application must be configured to automatically provide account management functions and these functions must immediately enforce the organization's current account policy. The automated mechanisms may reside within the application itself or may be offered by the operating system or other infrastructure providing automated account management capabilities. Automated mechanisms may be comprised of differing technologies that when placed together contain an overall automated mechanism supporting an organization's automated account management requirements. 

Account management functions include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to automatically notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephonic notification to report atypical system account usage.

"
  desc 'check', 'Review the ArcGIS for Server configuration to ensure mechanisms for supporting account management functions are provided. Substitute the target environment’s values for [bracketed] variables.

Verify ArcGIS for Server is utilizing Windows Users & Roles as its security store.

Navigate to [https://server.domain.com/arcgis]/admin/security/config (logon when prompted.)
Verify the “User Store Configuration” value = “Type: Windows”.
If the “User Store Configuration” value is set to “Type: Built-In”, this is a finding.

Verify the “Role Store Configuration” value = “Type: Windows”.
If the “Role store Configuration” value is set to “Type: Built-In”, this is a finding.

If the "Type" parameter of the "User Store Configuration" or "Role Store Configuration" is set to "Built-In", this is a finding.

This test requires the account performing the check to have "Administrator" privilege to the ArcGIS for Server site. This check can be performed remotely via HTTPS. This configuration is only valid when ArcGIS for Server has been deployed onto a Windows 2008 or later operating system that is a member of an Active Directory domain.

This control is not applicable for ArcGIS Server deployments configured to allow anonymous access.

This control is not applicable for ArcGIS Server deployments which are integrated with and protected by one or more third party DoD compliant certificate authentication solutions.'
  desc 'fix', 'Configure ArcGIS for Server to provide mechanisms for supporting account management functions. Substitute the target environment’s values for [bracketed] variables.

Configure ArcGIS for Server to utilize a Windows Domain for User and Role Management. Note: This procedure will disrupt existing systems connected to ArcGIS for Server:

Identify a system that will serve as the service endpoint for the ArcGIS for Server environment. This must be an Active Directory joined Windows 2008 R2 system with IIS 7.5 or later installed. If a Web Application Firewall (WAF), and/or Load Balancer serves as the user-connection endpoint, this system must be deployed on a trusted network behind these front-end technologies.

On this system (locally), perform the following steps:
Install the “ArcGIS Web Adaptor”.
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
  impact 0.7
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40540r642780_chk'
  tag severity: 'high'
  tag gid: 'V-237321'
  tag rid: 'SV-237321r879522_rule'
  tag stig_id: 'AGIS-00-000009'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-40503r642781_fix'
  tag satisfies: ['SRG-APP-000023', 'SRG-APP-000025', 'SRG-APP-000026', 'SRG-APP-000065', 'SRG-APP-000164', 'SRG-APP-000165', 'SRG-APP-000166', 'SRG-APP-000167', 'SRG-APP-000168', 'SRG-APP-000169', 'SRG-APP-000170', 'SRG-APP-000171', 'SRG-APP-000173', 'SRG-APP-000174']
  tag 'documentable'
  tag legacy: ['SV-79813', 'V-65323']
  tag cci: ['CCI-000015', 'CCI-000017', 'CCI-000018', 'CCI-000044', 'CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000196', 'CCI-000198', 'CCI-000199', 'CCI-000200', 'CCI-000205', 'CCI-001619']
  tag nist: ['AC-2 (1)', 'AC-2 (3) (d)', 'AC-2 (4)', 'AC-7 a', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (c)', 'IA-5 (1) (d)', 'IA-5 (1) (d)', 'IA-5 (1) (e)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']
end
