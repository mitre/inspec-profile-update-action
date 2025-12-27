control 'SV-213951' do
  title 'SQL Server must limit privileges to change software modules, to include stored procedures, functions and triggers, and links to software external to SQL Server.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications. 
 
Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', %q(Review server documentation to determine the process by which shared software libraries are monitored for change. Ensure the process alerts for changes in a file's ownership, modification dates, and hash value at a minimum.

If alerts do not at least hash their value, this is a finding.

To determine the location for these instance-specific binaries:

Launch SQL Server Management Studio (SSMS) >> Connect to the instance to be reviewed >> Right-click server name in Object Explorer >> Click Facets >> Select the Server facet >> Record the value for the "RootDirectory" facet property

TIP: Use the Get-FileHash cmdlet shipped with PowerShell 5.0 to get the SHA-2 hash of one or more files.)
  desc 'fix', 'Implement and document a process by which changes made to software libraries are monitored and alerted.

A PowerShell based hashing solution is one such process. The Get-FileHash command (https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.utility/get-filehash) can be used to compute the SHA-2 hash of one or more files.

Using the Export-Clixml command (https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Export-Clixml), a baseline can be established and exported to a file.

Using the Compare-Object command (https://technet.microsoft.com/en-us/library/ee156812.aspx), a comparison of the latest baseline versus the original baseline can be used to expose the differences.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15168r313636_chk'
  tag severity: 'medium'
  tag gid: 'V-213951'
  tag rid: 'SV-213951r879586_rule'
  tag stig_id: 'SQL6-D0-006600'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-15166r313637_fix'
  tag 'documentable'
  tag legacy: ['V-79165', 'SV-93871']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
