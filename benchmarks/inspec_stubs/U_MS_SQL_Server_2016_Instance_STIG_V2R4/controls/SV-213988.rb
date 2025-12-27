control 'SV-213988' do
  title 'Windows must enforce access restrictions associated with changes to the configuration of the SQL Server instance.'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system.  
 
When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system.  
 
Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Obtain a list of users who have privileged access to the server via the local Administrators group. 
 
Launch lusrmgr.msc 
Select Groups 
Double-click Administrators 
 
Alternatively, execute the following command in PowerShell: 

net localgroup administrators 
 
Check the server documentation to verify the users returned are authorized.  
 
If the users are not documented and authorized, this is a finding.'
  desc 'fix', 'Remove users from the local Administrators group who are not authorized.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15205r313747_chk'
  tag severity: 'medium'
  tag gid: 'V-213988'
  tag rid: 'SV-213988r754634_rule'
  tag stig_id: 'SQL6-D0-011500'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-15203r313748_fix'
  tag 'documentable'
  tag legacy: ['SV-93943', 'V-79237']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
