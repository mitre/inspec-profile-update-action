control 'SV-224469' do
  title 'CL/SuperSession APPCLASS member is not configured in accordance with the proper security requirements.'
  desc 'Product configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'a)	Review the member APPCLASS in the TLVPARM DD statement concatenation of the CL/Supersession STC procedure.  (This member is located in SYS3.OMEGAMON.qualifier.RLSPARM.)

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZCLS0043)

b)	If the parameters for the member APPCLASS are configured as follows, there is NO FINDING:

	VGWAPLST EXTERNAL=APPL

c)	If the parameters for the member APPCLASS are not configured as specified in (b) above, this is a FINDING.'
  desc 'fix', 'The Systems Programmer and IAO will ensure that the parameter options for member APPCLASS are coded to the below specifications.

Review the member APPCLASS in the TLVPARM DD statement concatenation of the CL/SuperSession STC procedure.  (This member is located in SYS3.OMEGAMON.qualifier.RLSPARM.)  Ensure all session manager security parameters and control options are in compliance according to the following: 

VGWAPLST EXTERNAL=APPL'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for RACF'
  tag check_id: 'C-26146r519761_chk'
  tag severity: 'medium'
  tag gid: 'V-224469'
  tag rid: 'SV-224469r519763_rule'
  tag stig_id: 'ZCLSR043'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26134r519762_fix'
  tag 'documentable'
  tag legacy: ['SV-27260', 'V-22691']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
