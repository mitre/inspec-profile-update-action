control 'SV-24606' do
  title 'A production DBMS installation should not coexist on the same DBMS host with other, non-production DBMS installations.'
  desc 'Production, development and other non-production DBMS installations have different access and security requirements.  Shared production/non-production DBMS installations secured at a production-level can impede development efforts whereas production/non-production DBMS installations secured at a development-level can lead to exploitation of production-level installations. Production DBMS installations should be kept separate from development, QA, TEST and other non-production DBMS systems.'
  desc 'check', 'Review the System Security Plan and interview the DBA and IAO to determine if the DBMS host contains production and non-production DBMS installations.

If the DBMS host contains both production and non-production DBMS installations or the production DBMS installation is being used for non-production efforts, determine if this allowance is documented in the System Security Plan and authorized by the IAO.

If not documented and authorized, this is a Finding.

NOTE: Though shared production/non-production DBMS installations was allowed under previous database STIG guidance, doing so may place it in violation of OS, Application, Network or Enclave STIG guidance. Ensure that any shared production/non-production DBMS installations meets STIG guidance requirements at all levels or mitigate any conflicts in STIG guidance with your DAA.'
  desc 'fix', 'Recommend establishing a dedicated DBMS host for production DBMS installations (See Checks DG0109 and DG0110).

A dedicated host system in this case refers to an instance of the operating system at a minimum.

The operating system may reside on a virtual host machine where supported by the DBMS vendor.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-936r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3803'
  tag rid: 'SV-24606r1_rule'
  tag stig_id: 'DG0017-ORACLE11'
  tag gtitle: 'DBMS shared production/development use'
  tag fix_id: 'F-26104r1_fix'
  tag 'documentable'
  tag responsibility: ['Database Administrator', 'Information Assurance Officer']
end
