control 'SV-224129' do
  title 'BMC CONTROL-O Started Task name is not properly identified / defined to the system ACP.'
  desc 'BMC CONTROL-O requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(ATTSTC)

Insure that the logonids(s) for the BMC CONTROL-O started task(s) includes the following:

STC
MUSASS
NO-SMC'
  desc 'fix', "The BMC CONTROL-O system programmer and the IAO will ensure that a product's Started Task(s) is properly Identified / defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

Example:

SET LID
CHANGE CONTROLO STC MUSASS NO-SMC"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-O for ACF2'
  tag check_id: 'C-25802r518833_chk'
  tag severity: 'medium'
  tag gid: 'V-224129'
  tag rid: 'SV-224129r518835_rule'
  tag stig_id: 'ZCTOA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25790r518834_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-32073']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
