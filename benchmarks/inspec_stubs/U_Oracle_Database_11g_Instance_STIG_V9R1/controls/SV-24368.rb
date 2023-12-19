control 'SV-24368' do
  title 'Audit trail data should be retained for one year.'
  desc 'Without preservation, a complete discovery of an attack or suspicious activity may not be determined.  DBMS audit data also contributes to the complete investigation of unauthorized activity and needs to be included in audit retention plans and procedures.'
  desc 'check', 'Review and verify the implementation of an audit trail retention policy.

Verify that audit data is maintained for a minimum of one year.

If audit data is not maintained for a minimum of one year, this is a Finding.'
  desc 'fix', 'Develop, document and implement an audit retention policy and procedures.

It is recommended that the most recent thirty days of audit logs remain available online.

After thirty days, the audit logs may be maintained offline.

Online maintenance provides for a more timely capability and inclination to investigate suspicious activity.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1001r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2507'
  tag rid: 'SV-24368r1_rule'
  tag stig_id: 'DG0030-ORACLE11'
  tag gtitle: 'DBMS audit data maintenance'
  tag fix_id: 'F-23729r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
