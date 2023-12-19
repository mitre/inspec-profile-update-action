control 'SV-224533' do
  title 'The Roscoe Resource Class will be defined or active in the ACP.'
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(SETROPTS)
-	DSMON.RPT(RACCDT) - Alternate list of active resource classes

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZROS0038)

Ensure that the ROSCOE resource class(es) is (are) defined and active.'
  desc 'fix', 'The IAO will ensure that the Product Resource Class(es) is (are) active.

Issue the following commands:

SETR CLASSACT(RO@RES)
SETR GENERIC(RO@RES)'
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for RACF'
  tag check_id: 'C-26216r520847_chk'
  tag severity: 'medium'
  tag gid: 'V-224533'
  tag rid: 'SV-224533r855201_rule'
  tag stig_id: 'ZROSR038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-26204r520848_fix'
  tag 'documentable'
  tag legacy: ['SV-24846', 'V-18011']
  tag cci: ['CCI-000336', 'CCI-002358']
  tag nist: ['CM-4 (2)', 'AC-25']
end
