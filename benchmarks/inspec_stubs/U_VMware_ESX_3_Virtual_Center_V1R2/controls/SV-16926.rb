control 'SV-16926' do
  title 'VirtualCenter Server assets are not configured with the correct posture in VMS.'
  desc 'Correctly configuring the VirtualCenter Server asset in VMS will ensure that the appropriate vulnerabilities are assigned to the asset. If the asset is not configured with the correct posture, vulnerabilities may be open on the asset.  These open vulnerabilities may allow an attacker to access the system.'
  desc 'check', 'If check ESX0869 is a finding, this should be marked a finding also.

If the assets are registered, verify that the following postures are registered.  The database may be SQL or Oracle. Use the appropriate database entry when applying the posture for the database. If any of the postures are not registered this is a finding.   For instance, the SQL Server 2005 posture will look as follows:  

Win2k3
Database SQL Server Installation 2005  
Database SQL Server Database 2005 – Model
Database SQL Server Database 2005 – Master
Database SQL Server Database 2005 – MSDB
Database SQL Server Database 2005 – TempDB
Database SQL Server Database 2005 – VCDB
Antivirus
Tomcat 5.x
VirtualCenter'
  desc 'fix', 'Register VirtualCenter Server with the correct posture in VMS.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16618r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15984'
  tag rid: 'SV-16926r1_rule'
  tag stig_id: 'ESX0872'
  tag gtitle: 'Register VirtualCenter Server with correct posture'
  tag fix_id: 'F-15975r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'VIVM-1'
end
