control 'SV-28967' do
  title 'Recovery procedures and technical system features exist to ensure that recovery is done
in a secure and verifiable manner.'
  desc 'A DBMS may be vulnerable to use of compromised data or other critical files during recovery. Use of compromised files could introduce maliciously altered application code, relaxed security settings or loss of data integrity. Where available, DBMS mechanisms to ensure use of only trusted files can help protect the database from this type of compromise during DBMS recovery.'
  desc 'check', 'Review DBMS recovery procedures or technical system features to determine if mechanisms exist and are in place to specify use of trusted files during DBMS recovery.

If recovery procedures do not exist or are not sufficient to ensure recovery is done in a secure and verifiable manner, this is a Finding.

If system features exist and are not employed or not employed sufficiently, this is a Finding.

If circumstances that can inhibit a trusted recovery are not documented and appropriate mitigating procedures have not been put in place, this is a Finding.'
  desc 'fix', 'Develop, document and implement DBMS recovery procedures and employ technical system features where supported by the DBMS to specify trusted files during DBMS recovery.

Ensure circumstances that can inhibit a trusted recovery are documented and appropriate mitigating procedures have been put in place.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29546r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15625'
  tag rid: 'SV-28967r1_rule'
  tag stig_id: 'DG0115-ORACLE11'
  tag gtitle: 'DBMS trusted recovery'
  tag fix_id: 'F-26648r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
