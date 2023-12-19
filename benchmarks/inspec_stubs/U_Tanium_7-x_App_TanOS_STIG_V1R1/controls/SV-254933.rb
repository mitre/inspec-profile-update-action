control 'SV-254933' do
  title 'The Tanium application must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure applications have a sufficient storage capacity in which to write the audit logs, applications need to be able to allocate audit record storage capacity. 

The task of allocating audit record storage capacity is usually performed during initial installation of the application and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.'
  desc 'check', 'Consult with the Tanium system administrator or database administrator to determine the memory plan needed for the database. 

1. Access the Tanium Server interactively.
 
2. Log on to the TanOS console as the user "tanadmin".

3. Enter "3" to access the "Tanium Support" menu. 

4. Enter "3" to access the "Tanium Database Operations" menu.  

5. Enter "D" to view "Memory Data Plan".

Work with the SIEM administrator to determine if an alert is configured when Disk Free Space of the Tanium SQL Server reaches below 25 percent.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Consult with the Tanium system administrator or database administrator to determine the memory plan needed for the database.   

1. Access the Tanium Server interactively.   

2. Log on to the TanOS SSH console as the user with tanadmin rights.  

3. Enter "3" to access the "Tanium Support" menu.   

4. Enter "3" to access the "Tanium Database Operations" menu.    

5. Enter "D" to access "Database Memory Plan" menu.  

6. Enter "S" to "Select DB Memory Plan".   

7. Enter "T","D","S","M","L", or "X" to confirm memory plan size, and then press "Enter" to continue.  

8. Enter "A" to save and apply the DB memory plan.   

Work with the SIEM administrator to determine if an alert is configured when Disk Free Space of the Tanium SQL Server reaches below 25 percent.  

If there is no alert configured, this is a finding.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58546r867697_chk'
  tag severity: 'medium'
  tag gid: 'V-254933'
  tag rid: 'SV-254933r867699_rule'
  tag stig_id: 'TANS-AP-000860'
  tag gtitle: 'SRG-APP-000357'
  tag fix_id: 'F-58490r867698_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
