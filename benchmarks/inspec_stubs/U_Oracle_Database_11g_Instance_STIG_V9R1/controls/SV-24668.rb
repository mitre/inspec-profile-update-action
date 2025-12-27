control 'SV-24668' do
  title 'Application user privilege assignment should be reviewed monthly or more frequently to ensure compliance with least privilege and documented policy.'
  desc 'Users granted privileges not required to perform their assigned functions are able to make unauthorized modifications to the production data or database. Monthly or more frequent periodic review of privilege assignments assures that organizational and/or functional changes are reflected appropriately.'
  desc 'check', 'Review policy, procedures and implementation evidence to determine if periodic reviews of user privileges by the IAO are being performed.

Evidence may consist of email or other correspondence that acknowledges receipt of periodic reports and notification of review between the DBA and IAO or other auditors as assigned.

If policy and procedures are incomplete or no evidence of implementation exists, this is a Finding.'
  desc 'fix', 'Develop, document and implement policy and procedures for periodic review of database user accounts and privilege assignments.

Include methods to provide evidence of review in the procedures to verify reviews occur in accordance with the procedures.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3821'
  tag rid: 'SV-24668r1_rule'
  tag stig_id: 'DG0080-ORACLE11'
  tag gtitle: 'DBMS application user privilege assignment review'
  tag fix_id: 'F-2583r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
