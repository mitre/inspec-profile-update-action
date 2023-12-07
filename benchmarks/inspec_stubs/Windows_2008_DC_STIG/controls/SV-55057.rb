control 'SV-55057' do
  title 'The Active Directory Domain object must be configured with proper audit settings.'
  desc 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a user or process to update the data without generating any tracking data.  The impact of missing audit data is related to the type of object.  A failure to capture audit data for objects used by identification, authentication, or authorization functions could degrade or eliminate the ability to track changes to access policy for systems or data. 

For Active Directory (AD), there are a number of critical object types in the domain naming context of the AD database for which auditing is essential.  This includes the Domain object.  Because changes to these objects can significantly impact access controls or the availability of systems, the absence of auditing data makes it impossible to identify the source of changes that impact the confidentiality, integrity, and availability of data and systems throughout an AD domain.  The lack of proper auditing can result in insufficient forensic evidence needed to investigate an incident and prosecute the intruder.'
  desc 'check', 'Verify the auditing configuration for the Domain object.

Open "Active Directory Users and Computers". (Available from various menus or run "dsa.msc".)
Ensure Advanced Features is selected in the View menu.
Select the domain being reviewed in the left pane.
Right click the domain name and select Properties.
Select the Security tab.
Select the Advanced button and then the Auditing tab.

If the audit settings on the Domain object are not at least as inclusive as those below, this is a finding.

Type - Fail
Name - Everyone
Access - Full Control
Inherited From - <not inherited>
Applies To - This object only

The success types listed below are defaults. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference, various Properties selections may also exist by default.

Two instances with the following summary information will be listed.
Type - Success
Name - Everyone
Access - (blank)
Inherited From - <not inherited>
Applies To - Special

Type - Success
Name - Domain Users
Access - All extended rights
Inherited From - <not inherited>
Applies To - This object only

Type - Success
Name - Administrators
Access - All extended rights
Inherited From - <not inherited>
Applies To - This object only

Type - Success
Name - Everyone
Access - Special
Inherited From - <not inherited>
Applies To - This object only
(Access - Special = Permissions: Write all properties, Modify permissions, Modify owner)'
  desc 'fix', 'Configure the audit settings for Domain object to include the following.

Type - Fail
Name - Everyone
Access - Full Control
Inherited From - <not inherited>
Applies To - This object only

The success types listed below are defaults. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference, various Properties selections may also exist by default.

Two instances with the following summary information will be listed.
Type - Success
Name - Everyone
Access - (blank)
Inherited From - <not inherited>
Applies To - Special

Type - Success
Name - Domain Users
Access - All extended rights
Inherited From - <not inherited>
Applies To - This object only

Type - Success
Name - Administrators
Access - All extended rights
Inherited From - <not inherited>
Applies To - This object only

Type - Success
Name - Everyone
Access - Special
Inherited From - <not inherited>
Applies To - This object only
(Access - Special = Permissions: Write all properties, Modify permissions, Modify owner)'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-48743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39326'
  tag rid: 'SV-55057r1_rule'
  tag stig_id: 'WINAU-000208-DC'
  tag gtitle: 'WINAU-000208-DC'
  tag fix_id: 'F-47929r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
