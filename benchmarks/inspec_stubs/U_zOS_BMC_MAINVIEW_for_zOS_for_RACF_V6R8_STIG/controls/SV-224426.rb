control 'SV-224426' do
  title 'BMC Mainview for z/OS Started Task name is not properly identified and/or defined to the system ACP.'
  desc 'BMC Mainview for z/OS requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

The BMC Mainview for z/OS started task(s) and/or batch job userid(s) is defined and is assigned the RACF PROTECTED attribute.'
  desc 'fix', "The BMC Mainview for z/OS system programmer and the IAO will ensure that a product's Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

au MV$CAS name('CAS, BMC Mainview for z/OS') owner(stc) dfltgrp(stc) nopass
au MV$PAS name('PAS, BMC Mainview for z/OS') owner(stc) dfltgrp(stc) nopass
au MV$MVS name('MVS, BMC Mainview for z/OS') owner(stc) dfltgrp(stc) nopass"
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for RACF'
  tag check_id: 'C-26103r518986_chk'
  tag severity: 'medium'
  tag gid: 'V-224426'
  tag rid: 'SV-224426r518988_rule'
  tag stig_id: 'ZMVZR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26091r518987_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-33839']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
