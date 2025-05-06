control 'SV-224457' do
  title 'CA 1 Tape Management Resource Class will be defined or active in the ACP.'
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(SETROPTS)
-	DSMON.RPT(RACCDT) - Alternate list of active resource classes

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZCA10038)

If the CA 1 Tape Management resource class(es) is (are) active, this is not a finding.'
  desc 'fix', 'Ensure that the following CA 1 Tape Management Resource Class(es) is (are) active.

CA@CMD
CA@APE

Use the following commands as an example:

SETROPTS CLASSACT(CA@CMD,CA@APE)'
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for RACF'
  tag check_id: 'C-26134r519506_chk'
  tag severity: 'medium'
  tag gid: 'V-224457'
  tag rid: 'SV-224457r519508_rule'
  tag stig_id: 'ZCA1R038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-26122r519507_fix'
  tag 'documentable'
  tag legacy: ['V-18011', 'SV-40668']
  tag cci: ['CCI-000336', 'CCI-002358']
  tag nist: ['CM-4 (2)', 'AC-25']
end
