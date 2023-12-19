control 'SV-224630' do
  title 'CA MIM Resource Sharing Started Task name will be properly identified and/or defined to the system ACP.'
  desc 'CA MIM Resource Sharing requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

Verify that the ACID(s) for the CA MIM Resource Sharing started task(s) is (are) properly defined.  If the following attributes are defined, this is not a finding.

FACILITY(STC, BATCH)
PASSWORD(xxxxxxxx,0)
SOURCE(INTRDR)
NOSUSPEND'
  desc 'fix', "The IAO working with the systems programmer will ensure the CA MIM Resource Sharing Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

TSS CREATE(MIMGR) TYPE(USER) -
	NAME('STC, CA MIM') DEPT(xxxx) -
	FAC(STC,BATCH) PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND"
  impact 0.5
  ref 'DPMS Target zOS CA MIM for TSS'
  tag check_id: 'C-26313r519659_chk'
  tag severity: 'medium'
  tag gid: 'V-224630'
  tag rid: 'SV-224630r519661_rule'
  tag stig_id: 'ZMIMT030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26301r519660_fix'
  tag 'documentable'
  tag legacy: ['SV-46212', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
