control 'SV-224467' do
  title 'CL/SuperSessions Resouce Class will be defined or active in the ACP.'
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(SETROPTS)

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZCLSR038)

If the CL/SuperSession resource class(es) is (are) active, this is not a finding.'
  desc 'fix', 'The IAO will ensure that the CL/SuperSession Resource Class(es) is (are) active.  The SYS3.OMEGAMON.qualifier.RLSPARM(KLVINNAM) member contains a "CLASSES=" entry, this entry identifies the member that contains the "VGWAPLST EXTERNAL=" entry.  The "VGWAPLST EXTERNAL=" entry identifies the resource class that is used by CL/SuperSession and this resource class will be active.  Current guidance identifies that APPL is the resource class identified in the above location.

Use the following commands as an example:

SETROPTS CLASSACT(APPL)'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for RACF'
  tag check_id: 'C-26144r519755_chk'
  tag severity: 'medium'
  tag gid: 'V-224467'
  tag rid: 'SV-224467r855141_rule'
  tag stig_id: 'ZCLSR038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-26132r519756_fix'
  tag 'documentable'
  tag legacy: ['V-18011', 'SV-27189']
  tag cci: ['CCI-000336', 'CCI-002358']
  tag nist: ['CM-4 (2)', 'AC-25']
end
