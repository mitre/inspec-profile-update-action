control 'SV-224287' do
  title 'CL/SuperSession KLVINNAM member must be configured in accordance to security requirements.'
  desc 'CL/SuperSession configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'If one of the following configuration settings is specified for each control point defined in the KLVINNAM member, this is not a finding.

DEFAULT DSNAME(SYS3.OMEGAMON.qualifier.RLSNAM) –
NORACF –
CLASSES=APPCLASS –
NODB –
EXIT=KLSA2NEV

(The following is for z/OS CAC logon processing)
DEFAULT DSNAME(SYS3.OMEGAMON.qualifier.RLSNAM) –
SAF –
CLASSES=APPCLASS –
NODB –
EXIT=KLSSFPTX'
  desc 'fix', 'Ensure that the parameter options for member KLVINNAM are coded to the below specifications.

(Note: The data set identified below is an example of a possible installation. The actual data set is determined when the product is actually installed on a system through the product’s installation guide and can be site specific.)

Review the member KLVINNAM in the TLVPARM DD statement concatenation of the CL/SuperSession STC procedure. (This member is located in SYS3.OMEGAMON.qualifier.RLSPARM.) Ensure all session manager security parameters and control options are in compliance according to the following: 

DEFAULT DSNAME(SYS3.OMEGAMON.qualifier.RLSNAM) –
      NORACF –
      CLASSES=APPCLASS –
      NODB –
      EXIT=KLSA2NEV

(The following is for z/OS CAC logon processing)
DEFAULT DSNAME(SYS3.OMEGAMON.qualifier.RLSNAM) –
      SAF –
      CLASSES=APPCLASS –
      NODB –
      EXIT=KLSSFPTX'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for ACF2'
  tag check_id: 'C-25960r767047_chk'
  tag severity: 'medium'
  tag gid: 'V-224287'
  tag rid: 'SV-224287r767048_rule'
  tag stig_id: 'ZCLSA042'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25948r519732_fix'
  tag 'documentable'
  tag legacy: ['V-22690', 'SV-27256']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
