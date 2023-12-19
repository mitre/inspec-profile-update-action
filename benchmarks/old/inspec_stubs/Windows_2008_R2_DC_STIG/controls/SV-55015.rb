control 'SV-55015' do
  title 'Active Directory Group Policy objects must be configured with proper audit settings.'
  desc 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a user or process to update the data without generating any tracking data.  The impact of missing audit data is related to the type of object.  A failure to capture audit data for objects used by identification, authentication, or authorization functions could degrade or eliminate the ability to track changes to access policy for systems or data. 

For Active Directory (AD), there are a number of critical object types in the domain naming context of the AD database for which auditing is essential.  This includes Group Policy objects.  Because changes to these objects can significantly impact access controls or the availability of systems, the absence of auditing data makes it impossible to identify the source of changes that impact the confidentiality, integrity, and availability of data and systems throughout an AD domain.  The lack of proper auditing can result in insufficient forensic evidence needed to investigate an incident and prosecute the intruder.'
  desc 'check', 'Review the auditing configuration for all Group Policy objects.

Open "Group Policy Management". (Available from various menus, or run "gpmc.msc".)

Navigate to "Group Policy Objects" in the domain being reviewed (Forest >> Domains >> Domain). 

For each Group Policy object: 

Select the Group Policy Object item in the left pane.

Select the "Delegation" tab in the right pane.

Select the "Advanced" button.

Select the "Advanced" button again and then the "Auditing" tab.

If the audit settings for any Group Policy object are not at least as inclusive as those below, this is a finding.

Type - Fail
Name - Everyone
Access - Full Control
Applies To - Descendant groupPolicyContainer objects

The three Success types listed below are defaults Inherited From the Parent Object. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference.

Type - Success
Name - Everyone
Access - Special (Permissions: Write all properties, Modify permissions; Properties: all "Write" type selected)
Inherited From - Parent Object
Applies To - Descendant groupPolicyContainer objects

Two instances with the following summary information will be listed.
Type - Success
Name - Everyone
Access - blank (Permissions: none selected; Properties: one instance - Write gPLink, one instance - Write gPOptions)
Inherited From - Parent Object
Applies To - Descendant Organization Unit objects'
  desc 'fix', 'Configure the audit settings for Group Policy objects to include the following.

This can be done at the Policy level in Active Directory to apply to all group policies.

Open "Active Directory Users and Computers" (available from various menus or run "dsa.msc").

Select "Advanced Features" from the "View" Menu.

Navigate to [Domain] >> System >> Policies in the left panel.

Right click "Policies", select "Properties".

Select the "Security" tab.

Select the "Advanced" button.

Select the "Auditing" tab.

Type - Fail
Name - Everyone
Access - Full Control
Applies To - Descendant groupPolicyContainer objects

The three Success types listed below are defaults Inherited From the Parent Object. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference.

Type - Success
Name - Everyone
Access - Special (Permissions: Write all properties, Modify permissions; Properties: all "Write" type selected)
Inherited From - Parent Object
Applies To - Descendant groupPolicyContainer objects

Two instances with the following summary information will be listed.
Type - Success
Name - Everyone
Access - blank (Permissions: none selected; Properties: one instance - Write gPLink, one instance - Write gPOptions)
Inherited From - Parent Object
Applies To - Descendant Organization Unit objects'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-79573r3_chk'
  tag severity: 'medium'
  tag gid: 'V-39325'
  tag rid: 'SV-55015r3_rule'
  tag stig_id: 'WINAU-000207-DC'
  tag gtitle: 'WINAU-000207-DC'
  tag fix_id: 'F-86711r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
