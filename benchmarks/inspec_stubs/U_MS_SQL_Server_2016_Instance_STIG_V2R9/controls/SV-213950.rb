control 'SV-213950' do
  title 'SQL Server must limit privileges to change software modules and links to software external to SQL Server.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications. 
 
Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', %q(Review Server documentation to determine the authorized owner and users or groups with modify rights for this SQL instance's binary files. Additionally check the owner and users or groups with modify rights for shared software library paths on disk.  
 
If any unauthorized users are granted modify rights or the owner is incorrect, this is a finding. 
 
To determine the location for these instance-specific binaries, Launch SQL Server Management Studio (SSMS) >> Connect to the instance to be reviewed >> Right-click server name in Object Explorer >> Click Facets >> Select the Server facet >> Record the value for the "RootDirectory" facet property. 
 
Navigate to the folder above, and review the "Binn" subdirectory.)
  desc 'fix', 'Change the ownership of all shared software libraries on disk to the authorized account. Remove any modify permissions granted to unauthorized users or groups.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15167r313633_chk'
  tag severity: 'medium'
  tag gid: 'V-213950'
  tag rid: 'SV-213950r879586_rule'
  tag stig_id: 'SQL6-D0-006500'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-15165r313634_fix'
  tag 'documentable'
  tag legacy: ['SV-93869', 'V-79163']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
