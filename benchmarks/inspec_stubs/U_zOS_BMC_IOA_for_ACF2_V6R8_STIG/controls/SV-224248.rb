control 'SV-224248' do
  title 'BMC IOA Started Task name must be properly identified and defined to the system ACP.'
  desc 'BMC IOA requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(ATTSTC)

Verify that the logonid(s) for the BMC IOA started task(s) is (are) properly defined.  If the following attributes are defined, this is not a finding.

STC
MUSASS
NO-SMC'
  desc 'fix', 'The IAO working with the systems programmer will ensure the BMC IOA Started Task(s) is (are) properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

SET LID
CHANGE IOAGATE STC MUSASS NO-SMC'
  impact 0.5
  ref 'DPMS Target zOS BMC IOA for ACF2'
  tag check_id: 'C-25921r518902_chk'
  tag severity: 'medium'
  tag gid: 'V-224248'
  tag rid: 'SV-224248r518904_rule'
  tag stig_id: 'ZIOAA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25909r518903_fix'
  tag 'documentable'
  tag legacy: ['SV-32076', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
