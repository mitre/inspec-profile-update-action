control 'SV-82297' do
  title 'Software, applications, and configuration files that are part of, or related to, the SQL Server  installation must be monitored to discover unauthorized changes.'
  desc 'When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of applications and tools related to SQL Server can potentially have significant effects on the overall security of the system. Only qualified and authorized individuals shall be allowed to obtain access to components related to SQL Server for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the software libraries or configuration can lead to unauthorized or compromised installations.

Of particular note in this context is that any software installed for auditing and/or audit file management must be protected and monitored.'
  desc 'check', "Verify that files and folders that are part of, or related to, the SQL Server 2014 installation have only the appropriate privileges. In Windows Explorer, right-click the file/folder, click Properties. On the Security tab, modify the security permissions, so that at most the following permissions are present:
Trusted Installer (Full Control)
SYSTEM (Full Control)
Administrators (Full Control) [See Note 1]
Users (Read, List Folder Contents, Read & Execute)
Creator Owner (Special Permissions - Full control - Subfolders and files only)
All Application Packages (Read & Execute) [Only as needed - see Note 2] 

If any less restrictive permissions are present (and not specifically justified and approved), this is a finding.

Verify that files and folders that are part of, or related to, the SQL Server 2014 installation have auditing enabled. Right-click on the file/folder, click Properties. On the Security tab, click Advanced. On the Auditing tab, verify that the following is set up on at least one audit:
Type: All
Principal: Everyone
Access: Modify
Applies to: This Folder, subfolder, and files [where applicable]

If the required audit settings are not configured, there is a risk that unauthorized changes to the software will go undetected, and this is a finding.

If a third-party security and data integrity tool is not used for monitoring and alerting files and folders based on cryptographic hashes, this is a finding.

If the tool does not verify files/folder locations as listed in the documentation, this is a finding.

Note 1: In the interest of separation of responsibilities with least privilege, consider granting Full Control only to SQL Database Administrators (or another appropriate group of administrators) and providing the local Administrators group with Read access only.

Note 2: Some files also require 'ALL APPLICATION PACKAGES (READ, EXECUTE)' permissions for certain functionality to work appropriately, and this is considered acceptable where those permissions are required. (All SQL Server files that require this access reside by default in the ..\\Microsoft SQL Server\\110\\ directory.)"
  desc 'fix', "Include locations of all files, libraries, scripts, and executables that are part of, or related to, the SQL Server 2014 installation in the documentation.

Ensure that files and folders that are part of, or related to, the SQL Server 2014 installation have only the following privileges. Right-click the file/folder, click Properties. On the Security tab, modify the security permissions, so that at most the following permissions are present:
Trusted Installer (Full Control)
SYSTEM (FULL CONTROL)
Administrators (FULL CONTROL)
Users (READ, LIST FOLDER CONTENTS, READ & EXECUTE)
Creator Owner (Special Permissions - Full control - Subfolders and files only)
All Application Packages (Read & Execute) [Only as needed - see Note 2]

Ensure that files and folders that are part of, or related to, the SQL Server 2014 installation have auditing enabled. Right-click on the file/folder, click Properties. On the Security tab, click Advanced. On the Auditing tab, use the Add or Edit buttons and the dialogs that follow from them, to set up the following on at least one audit:
Type: All
Principal: Everyone
Access: Modify
Applies to: This Folder, subfolder, and files [where applicable]

Deploy a third-party security and data integrity tool for monitoring and alerting files and folders based on cryptographic hashes, to verify files/folder locations as listed in the documentation.

Note 1: In the interest of separation of responsibilities with least privilege, consider granting Full Control only to SQL Database Administrators (or another appropriate group of administrators) and providing the local Administrators group with Read access only.

Note 2: Some files also require 'ALL APPLICATION PACKAGES (READ, EXECUTE)' permissions for certain functionality to work appropriately, and this is considered acceptable where those permissions are required. (All SQL Server files that require this access reside by default in the ..\\Microsoft SQL Server\\110\\ directory.)"
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68375r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67807'
  tag rid: 'SV-82297r1_rule'
  tag stig_id: 'SQL4-00-015350'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-73923r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
