control 'SV-224511' do
  title 'IBM System Display and Search Facility (SDSF) Resource Class will be active in the RACF.'
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(SETROPTS)
-	DSMON.RPT(RACCDT) - Alternate list of active resource classes

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZISF0038)

If the IBM System Display and Search Facility (SDSF) resource class(es) is (are) active, this is not a finding.'
  desc 'fix', 'The ISSO will ensure that the IBM SDSF Resource Class(es) is (are) active.

Use the following commands as an example:

SETROPTS CLASSACT(SDSF)'
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for RACF'
  tag check_id: 'C-26194r520382_chk'
  tag severity: 'medium'
  tag gid: 'V-224511'
  tag rid: 'SV-224511r856992_rule'
  tag stig_id: 'ZISFR038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-26182r840224_fix'
  tag 'documentable'
  tag legacy: ['SV-40831', 'V-18011']
  tag cci: ['CCI-000336', 'CCI-002358']
  tag nist: ['CM-4 (2)', 'AC-25']
end
