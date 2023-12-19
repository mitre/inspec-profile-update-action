control 'SV-24810' do
  title 'Remote administrative access to the database should be monitored by the IAO or IAM.'
  desc 'Remote administrative access to systems provides a path for access to and exploit of DBA privileges. Where the risk has been accepted to allow remote administrative access, it is imperative to instate increased monitoring of this access to detect any abuse or compromise.'
  desc 'check', 'If remote administrative access to the database is prohibited and is disabled (See Check DG0093), this check is Not a Finding.

Review policy, procedure and evidence of implementation for monitoring of remote administrative access to the database.

If monitoring procedures for remote administrative access are not documented or implemented, this is a Finding.'
  desc 'fix', 'Develop, document and implement policy and procedures to monitor remote administrative access to the DBMS.

The automated generation of a log report with automatic dissemination to the IAO/IAM may be used.

Require and store an acknowledgement of receipt and confirmation of review for the log report.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29377r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15118'
  tag rid: 'SV-24810r1_rule'
  tag stig_id: 'DG0159-ORACLE11'
  tag gtitle: 'Review of DBMS remote administrative access'
  tag fix_id: 'F-26402r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Manager', 'Information Assurance Officer']
end
