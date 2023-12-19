control 'SV-226128' do
  title 'Active Directory Group Policy objects must be configured with proper audit settings.'
  desc 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a user or process to update the data without generating any tracking data.  The impact of missing audit data is related to the type of object.  A failure to capture audit data for objects used by identification, authentication, or authorization functions could degrade or eliminate the ability to track changes to access policy for systems or data. 

For Active Directory (AD), there are a number of critical object types in the domain naming context of the AD database for which auditing is essential.  This includes Group Policy objects.  Because changes to these objects can significantly impact access controls or the availability of systems, the absence of auditing data makes it impossible to identify the source of changes that impact the confidentiality, integrity, and availability of data and systems throughout an AD domain.  The lack of proper auditing can result in insufficient forensic evidence needed to investigate an incident and prosecute the intruder.

'
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
Principal - Everyone
Access - Full Control
Applies to - This object and all descendant objects or Descendant groupPolicyContainer objects

The three Success types listed below are defaults inherited from the Parent Object. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference.

Type - Success
Principal - Everyone
Access - Special (Permissions: Write all properties, Modify permissions; Properties: all "Write" type selected)
Inherited from - Parent Object
Applies to - Descendant groupPolicyContainer objects

Two instances with the following summary information will be listed.
Type - Success
Principal - Everyone
Access - blank (Permissions: none selected; Properties: one instance - Write gPLink, one instance - Write gPOptions)
Inherited from - Parent Object
Applies to - Descendant Organization Unit Objects'
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
Principal - Everyone
Access - Full Control
Applies to - This object and all descendant objects or Descendant groupPolicyContainer objects

The three Success types listed below are defaults inherited from the Parent Object. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference.

Type - Success
Principal - Everyone
Access - Special (Permissions: Write all properties, Modify permissions; Properties: all "Write" type selected)
Inherited from - Parent Object
Applies to - Descendant groupPolicyContainer objects

Two instances with the following summary information will be listed.
Type - Success
Principal - Everyone
Access - blank (Permissions: none selected; Properties: one instance - Write gPLink, one instance - Write gPOptions)
Inherited from - Parent Object
Applies to - Descendant Organization Unit Objects'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27830r475707_chk'
  tag severity: 'medium'
  tag gid: 'V-226128'
  tag rid: 'SV-226128r794780_rule'
  tag stig_id: 'WN12-AU-000207-DC'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-27818r794779_fix'
  tag satisfies: ['SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['SV-51169', 'V-39325']
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
