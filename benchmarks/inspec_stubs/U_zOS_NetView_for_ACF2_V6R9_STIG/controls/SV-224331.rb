control 'SV-224331' do
  title 'NetView Started Task name must be properly identified / defined to the system ACP.'
  desc 'NetView requires a started task(s) that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-       ACF2CMDS.RPT(ATTSTC)

If the logonid for the NetView started task(s) includes MUSASS and NO-SMC, there is NO FINDING.

If the logonid for the NetView started task(s) is not defined or does not include MUSASS and/or NO-SMC, this is a FINDING.'
  desc 'fix', "The NetView system programmer and the ISSO will ensure that a product's Started Task(s) is properly Identified / defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

Example:

SET LID
CHANGE NETVIEW STC MUSASS NO-SMC"
  impact 0.5
  ref 'DPMS Target zOS NetView for ACF2'
  tag check_id: 'C-26008r520766_chk'
  tag severity: 'medium'
  tag gid: 'V-224331'
  tag rid: 'SV-224331r520768_rule'
  tag stig_id: 'ZNETA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25996r520767_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-28613']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
