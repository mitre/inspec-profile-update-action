control 'SV-24670' do
  title 'Automated notification of suspicious activity detected in the audit trail should be implemented.'
  desc "Audit record collection may quickly overwhelm storage resources and an auditor's ability to review it in a productive manner. Automated tools can provide the means to manage the audit data collected as well as present it to an auditor in an efficient way."
  desc 'check', 'If the database being reviewed is not a production database, this check is Not a Finding.

Interview the auditor or IAO to determine if an automated tool or procedure is used to report audit trail data. If an automated tool or procedure is not used, this is a Finding.'
  desc 'fix', 'Develop, document and implement database or host system procedures to report audit trail data in a form usable to detect unauthorized access to or usage of DBMS privileges, procedures or data.

You may also want to consider procuring a third-party auditing tool like Oracle Audit Vault with support for Oracle and other DBMS products within your environment.

NOTE: Audit data may contain sensitive information. The use of a single repository for audit data should be protected at the highest level based on the sensitivity of the databases being audited.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29190r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15102'
  tag rid: 'SV-24670r1_rule'
  tag stig_id: 'DG0083-ORACLE11'
  tag gtitle: 'DBMS audit report tools'
  tag fix_id: 'F-26206r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
