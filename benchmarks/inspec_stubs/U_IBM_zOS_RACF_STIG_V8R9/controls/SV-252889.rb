control 'SV-252889' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Started Task name is not properly identified / defined to the system ACP.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'From the ISPF Command Shell-
 enter ListUser

If the userid(s) for the IBM Integrated Crypto Service Facility (ICSF) started task is not defined to the security database, this is a finding.'
  desc 'fix', "Ensure that the started task for IBM Integrated Crypto Service Facility (ICSF) Started Task(s) is properly Identified / defined to the System ESM.

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.  Define the started task userid CSFSTART for IBM Integrated Crypto Service Facility (ICSF).

Example:

AU CSFSTART NAME('STC, ICSF') NOPASS -
	OWNER(STC) DFLTGRP(STC) -
	 DATA('START ICSF')"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-56345r822554_chk'
  tag severity: 'medium'
  tag gid: 'V-252889'
  tag rid: 'SV-252889r864492_rule'
  tag stig_id: 'RACF-IC-000040'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-56295r822555_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
