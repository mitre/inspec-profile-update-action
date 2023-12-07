control 'SV-205786' do
  title 'Windows Server 2019 Active Directory Domain object must be configured with proper audit settings.'
  desc 'When inappropriate audit settings are configured for directory service database objects, it may be possible for a user or process to update the data without generating any tracking data. The impact of missing audit data is related to the type of object. A failure to capture audit data for objects used by identification, authentication, or authorization functions could degrade or eliminate the ability to track changes to access policy for systems or data. 

For Active Directory (AD), there are a number of critical object types in the domain naming context of the AD database for which auditing is essential. This includes the Domain object. Because changes to these objects can significantly impact access controls or the availability of systems, the absence of auditing data makes it impossible to identify the source of changes that impact the confidentiality, integrity, and availability of data and systems throughout an AD domain. The lack of proper auditing can result in insufficient forensic evidence needed to investigate an incident and prosecute the intruder.

'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Review the auditing configuration for the Domain object.

Open "Active Directory Users and Computers" (available from various menus or run "dsa.msc").

Ensure "Advanced Features" is selected in the "View" menu.

Select the domain being reviewed in the left pane.

Right-click the domain name and select "Properties".

Select the "Security" tab.

Select the "Advanced" button and then the "Auditing" tab.

If the audit settings on the Domain object are not at least as inclusive as those below, this is a finding:

Type - Fail
Principal - Everyone
Access - Full Control
Inherited from - None
Applies to - This object only

The success types listed below are defaults. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference. Various Properties selections may also exist by default.

Two instances with the following summary information will be listed:

Type - Success
Principal - Everyone
Access - (blank)
Inherited from - None
Applies to - Special

Type - Success
Principal - Domain Users
Access - All extended rights
Inherited from - None
Applies to - This object only

Type - Success
Principal - Administrators
Access - All extended rights
Inherited from - None
Applies to - This object only

Type - Success
Principal - Everyone
Access - Special
Inherited from - None
Applies to - This object only
(Access - Special = Permissions: Write all properties, Modify permissions, Modify owner)'
  desc 'fix', 'Open "Active Directory Users and Computers" (available from various menus or run "dsa.msc").

Ensure "Advanced Features" is selected in the "View" menu.

Select the domain being reviewed in the left pane.

Right-click the domain name and select "Properties".

Select the "Security" tab.

Select the "Advanced" button and then the "Auditing" tab.

Configure the audit settings for Domain object to include the following:

Type - Fail
Principal - Everyone
Access - Full Control
Inherited from - None
Applies to - This object only

The success types listed below are defaults. Where Special is listed in the summary screens for Access, detailed Permissions are provided for reference. Various Properties selections may also exist by default.

Two instances with the following summary information will be listed:

Type - Success
Principal - Everyone
Access - (blank)
Inherited from - None
Applies to - Special

Type - Success
Principal - Domain Users
Access - All extended rights
Inherited from - None
Applies to - This object only

Type - Success
Principal - Administrators
Access - All extended rights
Inherited from - None
Applies to - This object only

Type - Success
Principal - Everyone
Access - Special
Inherited from - None
Applies to - This object only
(Access - Special = Permissions: Write all properties, Modify permissions, Modify owner.)'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6051r355720_chk'
  tag severity: 'medium'
  tag gid: 'V-205786'
  tag rid: 'SV-205786r852487_rule'
  tag stig_id: 'WN19-DC-000180'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-6051r355721_fix'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000468-GPOS-00212']
  tag 'documentable'
  tag legacy: ['SV-103211', 'V-93123']
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
