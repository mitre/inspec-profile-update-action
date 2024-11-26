control 'SV-24630' do
  title 'The audit logs should be periodically monitored to discover DBMS access using unauthorized applications.'
  desc 'Regular and timely reviews of audit records increases the likelihood of early discovery of suspicious activity. Discovery of suspicious behavior can in turn trigger protection responses to minimize or eliminate a negative impact from malicious activity. Use of unauthorized application to access the DBMS may indicate an attempt to bypass security controls.'
  desc 'check', 'If application access audit data is not available due to the lack of a local listener process or alternate method of auditing database access, this check is Not a Finding (see check DG0052).

Review the list of applications authorized to connect to the Oracle database as listed or noted in the System Security Plan.

If no list exists, this is a Finding.

Review evidence of audit log monitoring to detect use of unauthorized applications to access the database.

If no evidence exists or is incomplete, this is a Finding.'
  desc 'fix', 'Document applications authorized to access the DBMS in the System Security Plan.

Develop, document and implement a process to review log and trace files or the results from any alternate methods used to support database access auditing to detect connections from unauthorized applications.

Include in this process a method to generate and provide evidence of monitoring.

This may include automated or manual processes acknowledged by the auditor or IAO.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29157r1_chk'
  tag severity: 'low'
  tag gid: 'V-15611'
  tag rid: 'SV-24630r1_rule'
  tag stig_id: 'DG0054-ORACLE11'
  tag gtitle: 'DBMS software access audit review'
  tag fix_id: 'F-26168r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
