control 'SV-224479' do
  title 'IBM CSSMTP Started Task name is not properly identified and/or defined to the system ACP.'
  desc 'IBM CSSMTP requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

The IBM CSSMTP started task(s) and/or batch job userid(s) is defined and is assigned the RACF PROTECTED attribute.'
  desc 'fix', "The IBM CSSMTP system programmer and the IAO will ensure that a product's Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

A sample is provided here:

au CSSMTP name('IBM CSSMTP') owner(stc) dfltgrp(stc) nopass"
  impact 0.5
  ref 'DPMS Target zOS CSSMTP for RACF'
  tag check_id: 'C-26162r519863_chk'
  tag severity: 'medium'
  tag gid: 'V-224479'
  tag rid: 'SV-224479r519865_rule'
  tag stig_id: 'ZSMTR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26150r519864_fix'
  tag 'documentable'
  tag legacy: ['SV-37480', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
