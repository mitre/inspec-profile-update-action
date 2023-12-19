control 'SV-213913' do
  title 'The Certificate used for encryption must be backed up, stored offline and off-site.'
  desc 'Backup and recovery of the Certificate used for encryption is critical to the complete recovery of the database. Not having this key can lead to loss of data during recovery.'
  desc 'check', 'If the application owner and Authorizing Official have determined that encryption of data at rest is not required, this is not a finding.

Review procedures for, and evidence of backup of the Certificate used for encryption in the System Security Plan. 

If the procedures or evidence does not exist, this is a finding. 

If the procedures do not indicate offline and off-site storage of the Certificate used for encryption, this is a finding. 

If procedures do not indicate access restrictions to the Certificate backup, this is a finding.'
  desc 'fix', "Document and implement procedures to safely back up and store the Certificate used for encryption. Include in the procedures methods to establish evidence of backup and storage, and careful, restricted access and restoration of the Certificate. Also, include provisions to store the backup off-site. 

BACKUP CERTIFICATE 'CertificateName' TO FILE = 'path_to_file' 
WITH PRIVATE KEY (FILE = 'path_to_pvk', ENCRYPTION BY PASSWORD = 'password'); 

As this requires a password, take care to ensure it is not exposed to unauthorized persons or stored as plain text."
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15131r313171_chk'
  tag severity: 'medium'
  tag gid: 'V-213913'
  tag rid: 'SV-213913r508025_rule'
  tag stig_id: 'SQL6-D0-001800'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-15129r313172_fix'
  tag 'documentable'
  tag legacy: ['V-79089', 'SV-93795']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
