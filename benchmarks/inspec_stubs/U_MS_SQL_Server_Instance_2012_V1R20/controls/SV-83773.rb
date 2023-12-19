control 'SV-83773' do
  title 'Software, applications, and configuration files that are part of, or related to, the SQL Server 2012 installation must be audited.'
  desc 'When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of applications and tools related to SQL Server can potentially have significant effects on the overall security of the system. Only qualified and authorized individuals shall be allowed to obtain access to components related to SQL Server for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the software libraries or configuration can lead to unauthorized or compromised installations.

Of particular note in this context is that any software installed for auditing and/or audit file management must be protected and audited.'
  desc 'check', 'Obtain the SQL Server software directory location: from a command prompt, open the registry editor by typing regedit.exe and pressing [ENTER]. Navigate to the following registry location:
HKEY_LOCAL_MACHINE
>> SOFTWARE
>> Microsoft
>> Microsoft SQL Server
>> [INSTANCE NAME]
>> Setup
>> SQLBinRoot

Determine the location of separate but related softare, such as audit file management tools.

Verify that files and folders that are part of, or related to, the SQL Server 2012 installation have auditing enabled. Right-click on the file/folder, click Properties. On the Security tab, click Advanced. On the Auditing tab, verify 
that the following is set up on at least one audit:
Type: All
Principal: Everyone
Access: Modify
Applies to: This Folder, subfolder, and files [where applicable]

If the required audit settings are not configured, there is a risk that unauthorized changes to the software will go undetected, and this is a finding.'
  desc 'fix', 'Include locations of all files, libraries, scripts, and executables that are part of, or related to, the SQL Server 2012 installation in the documentation.

Ensure that files and folders that are part of, or related to, the SQL Server 2012 installation have auditing enabled. Right-click on the file/folder, click Properties. On the Security tab, click Advanced. On the Auditing tab, use the Add or Edit buttons and the dialogs that follow from them, to set up the following on at least one audit:
Type: All
Principal: Everyone
Access: Modify
Applies to: This Folder, subfolder, and files [where applicable]'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-69611r2_chk'
  tag severity: 'medium'
  tag gid: 'V-69169'
  tag rid: 'SV-83773r1_rule'
  tag stig_id: 'SQL2-00-015355'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-75357r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002717', 'CCI-002718']
  tag nist: ['SI-7 (6)', 'SI-7 (6)']
end
