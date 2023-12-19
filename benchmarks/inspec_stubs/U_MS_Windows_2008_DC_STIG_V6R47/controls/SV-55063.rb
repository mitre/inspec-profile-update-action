control 'SV-55063' do
  title 'The Active Directory Domain Controllers Organizational Unit (OU) object must be configured with proper audit settings.'
  desc 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a user or process to update the data without generating any tracking data.  The impact of missing audit data is related to the type of object.  A failure to capture audit data for objects used by identification, authentication, or authorization functions could degrade or eliminate the ability to track changes to access policy for systems or data. 

For Active Directory (AD), there are a number of critical object types in the domain naming context of the AD database for which auditing is essential.  This includes the Domain Controller OU object.  Because changes to these objects can significantly impact access controls or the availability of systems, the absence of auditing data makes it impossible to identify the source of changes that impact the confidentiality, integrity, and availability of data and systems throughout an AD domain.  The lack of proper auditing can result in insufficient forensic evidence needed to investigate an incident and prosecute the intruder.'
  desc 'check', 'Verify the auditing configuration for the Domain Controller OU object.

Open "Active Directory Users and Computers". (Available from various menus or run "dsa.msc".)
Ensure Advanced Features is selected in the View menu.
Select the Domain Controllers OU under the domain being reviewed in the left pane.
Right click the Domain Controllers OU object and select Properties.
Select the Security tab.
Select the Advanced button and then the Auditing tab.

If the audit settings on the Domain Controllers OU object are not at least as inclusive as those below, this is a finding.

Type - Fail
Name - Everyone
Access - Full Control
Inherited From - <not inherited>
Applies To - This object and all descendant objects

The success types listed below are defaults. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference, various Properties selections may also exist by default.

Type - Success
Name - Everyone
Access - Special
Inherited From - <not inherited>
Applies To - This object only
(Access - Special = Permissions: all create, delete, and modify permissions)

Type - Success
Name - Everyone
Access - Write all properties
Inherited From - <not inherited>
Applies To - This object and all descendant objects

Two instances with the following summary information will be listed.
Type - Success
Name - Everyone
Access - (blank)
Inherited From - (CN of domain)
Applies To - Descendant Organizational Unit objects'
  desc 'fix', 'Configure the audit settings for Domain Controllers OU object to include the following.

Type - Fail
Name - Everyone
Access - Full Control
Inherited From - <not inherited>

The success types listed below are defaults. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference, various Properties selections may also exist by default.

Type - Success
Name - Everyone
Access - Special
Inherited From - <not inherited>
Applies To - This object only
(Access - Special = Permissions: all create, delete, and modify permissions)

Type - Success
Name - Everyone
Access - Write all properties
Inherited From - <not inherited>
Applies To - This object and all descendant objects

Two instances with the following summary information will be listed.
Type - Success
Name - Everyone
Access - (blank)
Inherited From - (CN of domain)
Applies To - Descendant Organizational Unit objects'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-48750r2_chk'
  tag severity: 'medium'
  tag gid: 'V-39328'
  tag rid: 'SV-55063r1_rule'
  tag stig_id: 'WINAU-000210-DC'
  tag gtitle: 'WINAU-000210-DC'
  tag fix_id: 'F-47935r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
