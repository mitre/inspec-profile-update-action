control 'SV-226133' do
  title 'The Active Directory RID Manager$ object must be configured with proper audit settings.'
  desc 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a user or process to update the data without generating any tracking data.  The impact of missing audit data is related to the type of object.  A failure to capture audit data for objects used by identification, authentication, or authorization functions could degrade or eliminate the ability to track changes to access policy for systems or data. 

For Active Directory (AD), there are a number of critical object types in the domain naming context of the AD database for which auditing is essential.  This includes the RID Manager$ object.  Because changes to these objects can significantly impact access controls or the availability of systems, the absence of auditing data makes it impossible to identify the source of changes that impact the confidentiality, integrity, and availability of data and systems throughout an AD domain.  The lack of proper auditing can result in insufficient forensic evidence needed to investigate an incident and prosecute the intruder.

'
  desc 'check', 'Verify the auditing configuration for the RID Manager$ object.

Open "Active Directory Users and Computers".  (Available from various menus or run "dsa.msc".)
Ensure Advanced Features is selected in the View menu.
Select System under the domain being reviewed in the left pane.
Right-click the RID Manager$ object in the right pane and select Properties.
Select the Security tab.
Select the Advanced button and then the Auditing tab.

If the audit settings on the RID Manager$ object are not at least as inclusive as those below, this is a finding.

Type - Fail
Principal - Everyone
Access - Full Control
Inherited from - None

The success types listed below are defaults.  Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference, various Properties selections may also exist by default.

Type - Success
Principal - Everyone
Access - Special
Inherited from - None
 (Access - Special = Write all properties, All extended rights, Change RID master)

Two instances with the following summary information will be listed.
Type - Success
Principal - Everyone
Access - (blank)
Inherited from - (CN of domain)'
  desc 'fix', 'Configure the audit settings for RID Manager$ object to include the following.

Type - Fail
Principal - Everyone
Access - Full Control
Inherited from - None

The success types listed below are defaults.  Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference, various Properties selections may also exist by default.

Type - Success
Principal - Everyone
Access - Special
Inherited from - None
 (Access - Special = Write all properties, All extended rights, Change RID master)

Two instances with the following summary information will be listed.
Type - Success
Principal - Everyone
Access - (blank)
Inherited from - (CN of domain)'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27835r475722_chk'
  tag severity: 'medium'
  tag gid: 'V-226133'
  tag rid: 'SV-226133r852090_rule'
  tag stig_id: 'WN12-AU-000212-DC'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-27823r475723_fix'
  tag satisfies: ['SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['SV-51174', 'V-39330']
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
