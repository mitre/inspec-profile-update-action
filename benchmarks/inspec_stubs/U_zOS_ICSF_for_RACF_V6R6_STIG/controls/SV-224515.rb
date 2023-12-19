control 'SV-224515' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Started Task name is not properly identified / defined to the system ACP.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

b)	If the userid(s) for the IBM Integrated Crypto Service Facility (ICSF) started task is defined to the security database, there is NO FINDING.

c)	If the userid(s) for the IBM Integrated Crypto Service Facility (ICSF) started task is not defined to the security database, this is a FINDING.'
  desc 'fix', "The Systems Programmer and IAO will ensure that the started task for IBM Integrated Crypto Service Facility (ICSF) Started Task(s) is properly Identified / defined to the System ACP.

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.  Define the started task userid CSFSTART for IBM Integrated Crypto Service Facility (ICSF).

Example:

AU CSFSTART NAME('STC, ICSF') NOPASS -
	OWNER(STC) DFLTGRP(STC) -
	 DATA('START ICSF')"
  impact 0.5
  ref 'DPMS Target zOS ICSF for RACF'
  tag check_id: 'C-26198r520406_chk'
  tag severity: 'medium'
  tag gid: 'V-224515'
  tag rid: 'SV-224515r520408_rule'
  tag stig_id: 'ZICSR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26186r520407_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-30590']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
