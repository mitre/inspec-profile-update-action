control 'SV-24405' do
  title 'Audit trail data should be reviewed daily or more frequently.'
  desc 'Review of audit trail data provides a means for detection of unauthorized access or attempted access. Frequent and regularly scheduled reviews ensures that such access is discovered in a timely manner.'
  desc 'check', 'If the database being reviewed is not a production database, this check is Not a Finding.

Review policy and procedures documented or noted in the System Security plan as well as evidence of implementation for daily audit trail monitoring.  

If policy and procedures are not documented or evidence of implementation is not available, this is a Finding.'
  desc 'fix', 'Develop, document and implement policy and procedures to monitor audit trail data daily.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29224r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3827'
  tag rid: 'SV-24405r1_rule'
  tag stig_id: 'DG0095-ORACLE11'
  tag gtitle: 'DBMS audit trail data review'
  tag fix_id: 'F-26245r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
