control 'SV-224326' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Started Task name is not properly identified / defined to the system ACP.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(ATTSTC)

b)	If the logonid for the IBM Integrated Crypto Service Facility (ICSF) started task includes MUSASS and NO-SMC, there is NO FINDING.

c)	If the logonid for the IBM Integrated Crypto Service Facility (ICSF) started task does not include MUSASS and/or NO-SMC, this is a FINDING.'
  desc 'fix', 'The Systems Programmer and IAO will ensure that the started task for IBM Integrated Crypto Service Facility (ICSF) Started Task(s) is properly Identified / defined to the System ACP.

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.  Define the started task userid CSFSTART for IBM Integrated Crypto Service Facility (ICSF).

Example:

INSERT CSFSTART NAME(STC, ICSF) NO-SMC STC'
  impact 0.5
  ref 'DPMS Target zOS ICSF for ACF2'
  tag check_id: 'C-26003r520394_chk'
  tag severity: 'medium'
  tag gid: 'V-224326'
  tag rid: 'SV-224326r520396_rule'
  tag stig_id: 'ZICSA030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25991r520395_fix'
  tag 'documentable'
  tag legacy: ['SV-30578', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
