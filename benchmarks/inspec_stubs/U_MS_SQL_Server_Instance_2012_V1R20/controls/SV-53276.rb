control 'SV-53276' do
  title 'SQL Server must enforce password encryption for storage.'
  desc 'SQL Server must enforce password encryption when storing passwords. Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read and easily compromised.

Passwords stored in clear text are vulnerable to unauthorized disclosure. Database passwords should always be encoded or encrypted when stored internally or externally to SQL Server.'
  desc 'check', 'Since Windows security is being leveraged, this check applies to database configuration files, associated scripts, and applications external to SQL Server that access the database.  

Ask the DBA and/or IAO to determine if any SQL Server database objects, database configuration files, associated scripts, or applications defined as external to SQL Server that access the database/user environment files/settings contain database passwords. If any do, confirm that SQL Server passwords stored externally to the SQL Server are encoded or encrypted. If any passwords are stored in clear text, this is a finding.'
  desc 'fix', 'Develop, document, and maintain a list of SQL Server database objects, database configuration files, associated scripts, and applications defined within or external to SQL Server that access the database/user environment files/settings in the System Security Plan.

Record whether they do or do not contain SQL Server passwords. If passwords are present, ensure they are encrypted.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47577r2_chk'
  tag severity: 'medium'
  tag gid: 'V-40922'
  tag rid: 'SV-53276r2_rule'
  tag stig_id: 'SQL2-00-018600'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-46204r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
