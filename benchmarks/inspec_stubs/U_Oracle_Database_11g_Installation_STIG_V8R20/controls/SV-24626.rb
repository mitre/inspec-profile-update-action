control 'SV-24626' do
  title 'All applications that access the database should be logged in the audit trail.'
  desc 'Protections and privileges are designed within the database to correspond to access via authorized software. Use of unauthorized software to access the database could indicate an attempt to bypass established permissions. Reviewing the use of application software to the database can lead to discovery of unauthorized access attempts.'
  desc 'check', 'Review the DBMS audit trail to determine if the names [or unique identifiers] of applications used to connect to the database are included.

If an alternate method other than DBMS logging is authorized and implemented, review the audit trail to determine if the names [or unique identifiers] of applications used to connect to the database are included.

If application access to the DBMS is not being audited, this is a Finding.

If auditing does not capture the name [or unique identifier] of applications accessing the DBMS at a minimum, this is a Finding.'
  desc 'fix', 'Modify auditing to ensure audit records include identification of applications used to access the DBMS.

Ensure auditing captures the name [or unique identifier] of applications accessing the DBMS at a minimum.

Develop or procure a 3rd-party solution where native DBMS logging is not employed or does not capture required information.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29151r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3807'
  tag rid: 'SV-24626r1_rule'
  tag stig_id: 'DG0052-ORACLE11'
  tag gtitle: 'DBMS software access audit'
  tag fix_id: 'F-26162r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
