control 'SV-224253' do
  title 'BMC Mainview for z/OS Started Task name must be properly identified and/or defined to the system ACP.'
  desc 'BMC Mainview for z/OS requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-       ACF2CMDS.RPT(ATTSTC)

Insure that the logonids(s) for the BMC Mainview for z/OS started task(s) includes the following:

STC
NO-SMC'
  desc 'fix', "Ensure that a product's Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

Example:

SET LID
INSERT MV$CAS STC NO-SMC
INSERT MV$PAS STC NO-SMC
INSERT MV$MVS STC NO-SMC"
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for ACF2'
  tag check_id: 'C-25926r518968_chk'
  tag severity: 'medium'
  tag gid: 'V-224253'
  tag rid: 'SV-224253r518970_rule'
  tag stig_id: 'ZMVZA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25914r518969_fix'
  tag 'documentable'
  tag legacy: ['SV-33838', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
