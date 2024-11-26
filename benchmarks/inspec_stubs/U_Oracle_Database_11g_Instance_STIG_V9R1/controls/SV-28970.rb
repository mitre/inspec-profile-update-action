control 'SV-28970' do
  title 'Transaction logs should be periodically reviewed for unauthorized modification of data.'
  desc 'Unauthorized or malicious changes to data compromise the integrity and usefulness of the data. Auditing changes to data supports accountability and non-repudiation. Auditing changes to data may be provided by the application accessing the DBMS or may depend upon the DBMS auditing functions. When DBMS auditing is used, the DBA is responsible for ensuring the auditing configuration meets the application design requirements.'
  desc 'check', 'If the application does not require auditing using DBMS features, this check is Not Applicable.

Review the application System Security Plan for requirements for database configuration for auditing changes to application data.

If the application requires DBMS auditing for changes to data, review the database audit configuration against the application requirement. If the auditing does not comply with the requirement, this is a Finding.'
  desc 'fix', 'Configure database data auditing to comply with the requirements of the application.

Document auditing requirements in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29549r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15133'
  tag rid: 'SV-28970r1_rule'
  tag stig_id: 'DG0031-ORACLE11'
  tag gtitle: 'DBMS audit of changes to data'
  tag fix_id: 'F-26651r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
