control 'SV-224346' do
  title 'Tivoli Asset Discovery for z/OS (TADz) Started Task name(s) must be properly identified / defined to the system ACP.'
  desc 'Tivoli Asset Discovery for z/OS (TADz) requires a started task(s) that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system Access Control Program (ACP), it allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(LOGONIDS)

Ensure the following field is completed for each STC logonid for the product:

STC

Ensure the following field is completed for each Batch logonid for the product:

JOB

If the logonids specified in (b) and/or (c) have all the required field is completed, this is not a FINDING.

If the logonids specified in (b) and/or (c) do not have the above field completed, this is a FINDING.'
  desc 'fix', "The TADz system programmer and the ISSO will ensure that a product's Started Task(s) is properly identified / defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

Example:

SET LID
CHANGE TADZMON STC"
  impact 0.5
  ref 'DPMS Target zOS TADz for ACF2'
  tag check_id: 'C-26023r520895_chk'
  tag severity: 'medium'
  tag gid: 'V-224346'
  tag rid: 'SV-224346r520897_rule'
  tag stig_id: 'ZTADA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26011r520896_fix'
  tag 'documentable'
  tag legacy: ['SV-28612', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
