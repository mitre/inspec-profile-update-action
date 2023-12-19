control 'SV-251639' do
  title 'IDMS must restrict the use of code that provides elevated privileges to specific instances.'
  desc 'When a user has elevated privileges, they may be able to deliberately or inadvertently make alterations to the DBMS structure or data.'
  desc 'check', 'Review the system documentation, database, and DBMS security configuration (in SRTT and ESM), source code for DBMS internal logic, source code of external modules invoked by the DBMS, and source code of the application(s) using the database.

If elevation of DBMS privileges is utilized but not documented, this is a finding.

If elevation of DBMS privileges is documented, but not implemented as described in the documentation, this is a finding.

If the privilege-elevation logic can be invoked in ways other than intended, or in contexts other than intended, or by subjects/principals other than intended, this is a finding.'
  desc 'fix', 'Determine where, when, how, and by what principals/subjects elevated privilege is needed.

Modify the database and DBMS security configuration (in SRTT and external security manager [ESM]), DBMS internal logic, external modules invoked by the DBMS, and the application(s) using the database, to ensure privilege elevation is used only as required.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55074r807782_chk'
  tag severity: 'medium'
  tag gid: 'V-251639'
  tag rid: 'SV-251639r855277_rule'
  tag stig_id: 'IDMS-DB-000690'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-55028r807783_fix'
  tag 'documentable'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
