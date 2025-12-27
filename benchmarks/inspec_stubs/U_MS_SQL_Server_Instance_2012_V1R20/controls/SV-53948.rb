control 'SV-53948' do
  title 'The Service Master Key must be backed up, stored offline and off-site.'
  desc 'Backup and recovery of the Service Master Key may be critical to the complete recovery of the database. Not having this key can lead to loss of data during recovery.'
  desc 'check', 'Review procedures for, and evidence of backup of, the SQL Server Service Master Key in the System Security Plan.

If the procedures or evidence do not exist, this is a finding.

If the procedures do not indicate offline and off-site storage of the Service Master Key, this is a finding.

If procedures do not indicate access restrictions to the Service Master Key backup, this is a finding.'
  desc 'fix', "Document and implement procedures to safely back up and store the Service Master Key. Include in the procedures methods to establish evidence of backup and storage, and careful, restricted access and restoration of the Service Master Key. Also, include provisions to store the key off-site.
BACKUP SERVICE MASTER KEY TO FILE = 'path_to_file'
ENCRYPTION BY PASSWORD = 'password'"
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47954r3_chk'
  tag severity: 'medium'
  tag gid: 'V-41419'
  tag rid: 'SV-53948r3_rule'
  tag stig_id: 'SQL2-00-024500'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-46847r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
