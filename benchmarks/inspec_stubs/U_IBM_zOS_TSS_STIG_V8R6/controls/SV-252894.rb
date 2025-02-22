control 'SV-252894' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Started Task name is not properly identified / defined to the system ACP.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Review the IBM Integrated Crypto Service Facility (ICSF) STC/Batch ACID(s) for the following:

___	Is defined with Facility of STC and/or BATCH.

___	Is sourced to the INTRDR.

c)	If all of the above are true this is not a finding

d)	If any of the above is untrue this is a finding.'
  desc 'fix', "The Systems Programmer and IAO will ensure that the started task for IBM Integrated Crypto Service Facility (ICSF) Started Task(s) is properly Identified / defined to the System ACP.

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.  Define the started task userid CSFSTART for IBM Integrated Crypto Service Facility (ICSF).

Example:

TSS CRE(CSFSTART) DEPT(Dept) NAME('ICSF STC') -
	FAC(STC) PASSWORD(password,0) -
	SOURCE(INTRDR)"
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-56350r822569_chk'
  tag severity: 'medium'
  tag gid: 'V-252894'
  tag rid: 'SV-252894r822571_rule'
  tag stig_id: 'TSS0-IC-000040'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-56300r822570_fix'
  tag 'documentable'
  tag legacy: ['SV-30591', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
