control 'SV-224468' do
  title 'CL/SuperSession KLVINNAM member must be configured in accordance to security requirements.'
  desc 'CL/SuperSession configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'Review the member KLVINNAM in the TLVPARM DD statement concatenation of the CL/SuperSession STC procedure. (This member is located in SYS3.OMEGAMON.qualifier.RLSPARM.)

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

- PDI(ZCLS0042)

If one of the following configuration settings is specified for each control point defined in the KLVINNAM member, this is not a finding.

DEFAULT DSNAME(SYS3.OMEGAMON.qualifier.RLSNAM) –
RACF –
CLASSES=APPCLASS –
NODB
EXIT=KLVRACVR 

(The following is for z/OS CAC logon processing)
DEFAULT DSNAME(SYS3.OMEGAMON.qualifier.RLSNAM) –
SAF – (RACF is also acceptable)
CLASSES=APPCLASS –
NODB –
EXIT=KLSNFPTX'
  desc 'fix', 'Ensure that the parameter options for member KLVINNAM are coded to the below specifications.

(Note: The data set identified below is an example of a possible installation. The actual data set is determined when the product is actually installed on a system through the product’s installation guide and can be site specific.)

Review the member KLVINNAM in the TLVPARM DD statement concatenation of the CL/SuperSession STC procedure. (This member is located in SYS3.OMEGAMON.qualifier.RLSPARM.) Ensure all session manager security parameters and control options are in compliance according to the following: 

DEFAULT DSNAME(SYS3.OMEGAMON.qualifier.RLSNAM) –
      RACF –
      CLASSES=APPCLASS –
      NODB
      EXIT=KLVRACVR 



(The following is for z/OS CAC logon processing)
DEFAULT DSNAME(SYS3.OMEGAMON.qualifier.RLSNAM) –
      SAF – (RACF is also acceptable)      CLASSES=APPCLASS –
      NODB –
      EXIT=KLSNFPTX'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for RACF'
  tag check_id: 'C-26145r768741_chk'
  tag severity: 'medium'
  tag gid: 'V-224468'
  tag rid: 'SV-224468r768742_rule'
  tag stig_id: 'ZCLSR042'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26133r519759_fix'
  tag 'documentable'
  tag legacy: ['SV-27257', 'V-22690']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
