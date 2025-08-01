control 'SV-224339' do
  title 'ROSCOE Started Task name is not properly identified / defined to the system ACP.'
  desc 'Products that require a started task will require that the started task be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(LOGONIDS)

b)	Ensure the following fields are completed for each STC logonid for the product:

STC
JOBFROM
MUSASS
NO-SMC

c)	Ensure the following fields are completed for each Batch logonid for the product:

JOB
JOBFROM
MUSASS
NO-SMC

d)	If the logonids specified in (b) and/or (c) have all the required fields are completed, this is not a FINDING.

e)	If the logonids specified in (b) and/or (c) do not have all the above fields completed, this is a FINDING.'
  desc 'fix', "The ROSCOE system programmer and the IAO will ensure that a product's Started Task(s) is properly Identified / defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

Example:

SET LID
CHANGE ROSCOE JOBFROM MUSASS NO-SMC"
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for ACF2'
  tag check_id: 'C-26016r520823_chk'
  tag severity: 'medium'
  tag gid: 'V-224339'
  tag rid: 'SV-224339r520825_rule'
  tag stig_id: 'ZROSA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26004r520824_fix'
  tag 'documentable'
  tag legacy: ['SV-21877', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
