control 'SV-223242' do
  title 'SharePoint must ensure remote sessions for accessing security functions and security-relevant information are audited.'
  desc 'Remote access is any access to an organizational information system by a user (or an information system) communicating through an external, non-organization-controlled network (e.g., the Internet). Examples of remote access methods include dial-up, broadband, and wireless.

Remote network and system access is accomplished by leveraging common communication protocols to establish a remote connection. These connections will typically originate over either the public Internet or the Public Switched Telephone Network (PSTN). Neither of these Internetworking mechanisms is private or secure, and they do not, by default, restrict access to networked resources once connectivity is established.

Numerous best practices are employed to protect remote connections, such as utilizing encryption to protect data sessions and firewalls to restrict and control network connectivity. In addition to these protections, auditing must also be utilized in order to track system activity, assist in diagnosing system issues and provide evidence needed for forensic investigations post security incident.

When organizations define security-related application functions or security-related application information, it is incumbent upon the application providing access to that data to ensure auditing of remote connectivity to those resources occurs in support of organizational requirements.

Remote access to security functions (e.g., user management, audit log management, etc.) and security-relevant information requires the activity be audited by the organization. Any application providing remote access must support organizational requirements to audit access or organization-defined security functions and security-relevant information.'
  desc 'check', 'Note: If no unsanctioned information is transferred, and has been documented by the Data Owner, IRM is not required. This requirement is Not Applicable.

Review the SharePoint server configuration to ensure remote sessions for accessing security functions and security-relevant information are audited.

Verify that SharePoint audit settings are configured at the site collection level in accordance with your system security plan.

To verify audit settings at the site collection level for each site collection level subject to auditing per the SSP:

Click Settings >> Site settings.

If not at the root of your site collection, under Site Collection Administration, click Go to top level site settings. (Note: The Site Collection Administration section will not be available if you do not have the necessary permissions)

On the Site Settings page, under Site Collection Administration, click Site collection audit settings.

On the Configure Audit Settings page verify the events that are required to audit are selected, and then click OK. If nothing is selected, or the selected criteria do not match the SSP, this is a finding.'
  desc 'fix', 'Configure the SharePoint server configuration to audit remote sessions for accessing security functions and security-relevant information.

In Central Administration, click on Security.

On the Security page, in the Information policy list, click "Configure information rights management".

Select "Use the default RMS server specified in Active Directory", or identify a specific server by selecting "Use this RMS server:" and entering the server name.

Configure information management policies in accordance with the system security plan requirements.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24915r430786_chk'
  tag severity: 'medium'
  tag gid: 'V-223242'
  tag rid: 'SV-223242r612235_rule'
  tag stig_id: 'SP13-00-000025'
  tag gtitle: 'SRG-APP-000016'
  tag fix_id: 'F-24903r430787_fix'
  tag 'documentable'
  tag legacy: ['SV-74371', 'V-59941']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
