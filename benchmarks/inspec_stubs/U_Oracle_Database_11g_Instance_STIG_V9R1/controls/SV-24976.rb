control 'SV-24976' do
  title 'Audit records should include the reason for blacklisting or disabling DBMS connections or accounts.'
  desc 'Records of any disabling or locking of account actions taken by the DBMS can contain information valuable to decisions to employ additional responsive actions.'
  desc 'check', 'Review audit settings for disabling or locking account events based on event failures.

If the settings are not configured to include the cause of the lock or disabling, this is a Finding.'
  desc 'fix', 'Determine and implement audit settings that will collect and store the cause of any DBMS account or connection lock or disabling actions taken by the DBMS.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-28646r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15647'
  tag rid: 'SV-24976r1_rule'
  tag stig_id: 'DG0146-ORACLE11'
  tag gtitle: 'DBMS connection block audit'
  tag fix_id: 'F-3790r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
