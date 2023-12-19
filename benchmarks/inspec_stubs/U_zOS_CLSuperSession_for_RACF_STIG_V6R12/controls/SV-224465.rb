control 'SV-224465' do
  title 'CL/SuperSession Started Task name is not properly identified / defined to the system ACP.'
  desc 'CL/SuperSession requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

b)	If the userid for the CL/SUPERSESSION started task is defined to the security database, there is NO FINDING.

c)	If the userid for the CL/SUPERSESSION started task is not defined to the security database, this is a FINDING.'
  desc 'fix', "The Systems Programmer and IAO will ensure that the started task for CL/SuperSession is properly defined.

Review all session manager security parameters and control options for compliance. Develop a plan of action and implement the changes as specified.

Define the started task userid KLS for CL/SuperSession.

Example:

AU KLS NAME('STC, SUPERSESSION') NOPASS -
 OWNER(STC) DFLTGRP(STC) -
 DATA('START CL SUPERSESSION')"
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for RACF'
  tag check_id: 'C-26142r519749_chk'
  tag severity: 'medium'
  tag gid: 'V-224465'
  tag rid: 'SV-224465r519751_rule'
  tag stig_id: 'ZCLSR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26130r519750_fix'
  tag 'documentable'
  tag legacy: ['SV-28591', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
