control 'SV-224420' do
  title 'BMC IOA Started Task name must be properly identified and defined to the system ACP.'
  desc 'BMC IOA requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

Verify that the userid(s) for the BMC IOA started task(s) is (are) properly defined.  If the following attributes are defined, this is not a finding.

PROTECTED'
  desc 'fix', "The IAO working with the systems programmer will ensure the BMC IOA Started Task(s) is (are) properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

au IOAGATE name('stc, BMC IOA') owner(stc) dfltgrp(stc) nopass"
  impact 0.5
  ref 'DPMS Target zOS BMC IOA for RACF'
  tag check_id: 'C-26097r518923_chk'
  tag severity: 'medium'
  tag gid: 'V-224420'
  tag rid: 'SV-224420r518925_rule'
  tag stig_id: 'ZIOAR030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26085r518924_fix'
  tag 'documentable'
  tag legacy: ['SV-32077', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
