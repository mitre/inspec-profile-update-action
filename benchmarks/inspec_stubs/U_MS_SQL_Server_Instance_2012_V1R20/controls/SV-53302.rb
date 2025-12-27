control 'SV-53302' do
  title 'Software, applications, and configuration files that are part of, or related to, the SQL Server 2012 installation must be monitored to discover unauthorized changes.'
  desc 'When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of applications and tools related to SQL Server can potentially have significant effects on the overall security of the system. Only qualified and authorized individuals shall be allowed to obtain access to components related to SQL Server for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the software libraries or configuration can lead to unauthorized or compromised installations.

Of particular note in this context is that any software installed for auditing and/or audit file management must be protected and monitored.'
  desc 'check', 'If a security and data integrity tool is not used for monitoring and alerting files and folders based on cryptographic hashes, this is a finding.

If the tool does not verify files/folder locations as listed in the documentation, this is a finding.'
  desc 'fix', 'Include locations of all files, libraries, scripts, and executables that are part of, or related to, the SQL Server 2012 installation in the documentation.

Deploy a security and data integrity tool for monitoring and alerting files and folders based on cryptographic hashes, to verify files/folder locations as listed in the documentation.'
  impact 0.7
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47603r8_chk'
  tag severity: 'high'
  tag gid: 'V-40948'
  tag rid: 'SV-53302r5_rule'
  tag stig_id: 'SQL2-00-015350'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-46230r8_fix'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-002716', 'CCI-002718']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9', 'SI-7 (6)', 'SI-7 (6)']
end
