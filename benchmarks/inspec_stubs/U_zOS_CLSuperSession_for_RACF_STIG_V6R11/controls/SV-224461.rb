control 'SV-224461' do
  title 'CL/SuperSession profile options are set improperly.'
  desc 'Product configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'a)	The following steps are necessary for reviewing the CL/SuperSession options:

1)	Request on-line access from the site administrator to view CL/SuperSession parameter settings.
2)	Once access to the CL/SuperSession Main Menu has been obtained, select the option for the ADMINISTRATOR menu.
3)	From the ADMINISTRATOR menu, select the option for the PROFILE SELECTION menu.
4)	From the PROFILE SELECTION menu, select the View GLOBAL Profile option.
5)	After selection of the View GLOBAL Profile option, the Update GLOBAL Profile menu appears.  From this menu select the profile to be reviewed:

-	To view the Common profile select:	_Common
-	To view the SUPERSESSION profile select:	_SupSess

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZCLS0040)

b)	Compare the security parameters as specified in the Required CL/SuperSession Common Profile Options and Required CL/Superssion Profile Options Tables in the z/OS STIG Addendum against the CL/SuperSession Profile options.

c)	If all options as specified in the Required CL/SuperSession Common Profile Options and Required CL/Superssion Profile Options Tables in the z/OS STIG Addendum are in effect, there is NO FINDING.

d)	If any of the options as specified in the Required CL/SuperSession Common Profile Options and Required CL/Superssion Profile Options Tables in the z/OS STIG Addendum is not in effect, this is a FINDING.'
  desc 'fix', 'The Systems Programmer and IAO will review all session manager security parameters and control options for compliance with the requirements of the z/OS STIG Addendum Required CL/SuperSession Common Profile Options and Required CL/SuperSession Profile Options Tables.  Verify that the options are set properly.'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for RACF'
  tag check_id: 'C-26138r519737_chk'
  tag severity: 'medium'
  tag gid: 'V-224461'
  tag rid: 'SV-224461r519739_rule'
  tag stig_id: 'ZCLS0040'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26126r519738_fix'
  tag 'documentable'
  tag legacy: ['V-18014', 'SV-27197']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
