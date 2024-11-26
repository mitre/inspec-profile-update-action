control 'SV-213974' do
  title 'The Master Key must be backed up, stored offline and off-site.'
  desc 'Backup and recovery of the Master Key may be critical to the complete recovery of the database.  Not having this key can lead to loss of data during recovery.'
  desc 'check', 'If the application owner and Authorizing Official have determined that encryption of data at rest is not required, this is not a finding. 
 
Review procedures for, and evidence of backup of, the Master Key in the System Security Plan.  
 
If the procedures or evidence does not exist, this is a finding.  
 
If the procedures do not indicate offline and off-site storage of the Master Key, this is a finding.  
 
If procedures do not indicate access restrictions to the Master Key backup, this is a finding.'
  desc 'fix', "Document and implement procedures to safely back up and store the Master Key. Include in the procedures methods to establish evidence of backup and storage, and careful, restricted access and restoration of the Master Key. Also, include provisions to store the key off-site.  
 
BACKUP MASTER KEY TO FILE = 'path_to_file'  
ENCRYPTION BY PASSWORD = 'password';  
 
As this requires a password, take care to ensure it is not exposed to unauthorized persons or stored as plain text."
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15191r313705_chk'
  tag severity: 'medium'
  tag gid: 'V-213974'
  tag rid: 'SV-213974r879642_rule'
  tag stig_id: 'SQL6-D0-009700'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-15189r313706_fix'
  tag 'documentable'
  tag legacy: ['SV-93915', 'V-79209']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
