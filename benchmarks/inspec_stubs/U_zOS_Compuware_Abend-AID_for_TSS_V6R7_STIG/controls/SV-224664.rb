control 'SV-224664' do
  title 'Compuware Abend-AID Started Task name will be properly identified and/or defined to the system ACP.'
  desc 'Compuware Abend-AID requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', "Default Finding Details:
The product's started task(s) is (are) not properly identified and/or defined to the System ACP.

Check:
Refer to the following report produced by the TSS Data Collection:

- TSSCMDS.RPT(@ACIDS)

Verify that the ACID(s) for the Compuware Abend-AID started task(s) is (are) properly defined. If the following attributes are defined, this is not a finding.

FACILITY(STC, BATCH)
PASSWORD(xxxxxxxx,0)
SOURCE(INTRDR)
NOSUSPEND"
  desc 'fix', "The ISSO working with the systems programmer will ensure the Compuware Abend-AID Started Task(s) is properly identified and/or defined to the System ACP. 

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.

The following commands are provided as a sample for defining Started Task(s):

TSS CREATE(BDCAS) TYPE(USER) -
	NAME('STC, Compuware Abend-AID') DEPT(xxxx) -
	FAC(STC,BATCH) PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND
TSS CREATE(TDCAS) TYPE(USER) -
	NAME('STC, Compuware Abend-AID for CICS') DEPT(xxxx) -
	FAC(STC,BATCH) PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND
TSS CREATE(AAVIEWER) TYPE(USER) -
	NAME('STC, Compuware Abend-AID Viewer') DEPT(xxxx) -
	FAC(STC,BATCH) PASS(xxxxxxxx,0) -
	SOURCE(INTRDR) NOSUSPEND"
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for TSS'
  tag check_id: 'C-26347r868612_chk'
  tag severity: 'medium'
  tag gid: 'V-224664'
  tag rid: 'SV-224664r868614_rule'
  tag stig_id: 'ZAIDT030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26335r868613_fix'
  tag 'documentable'
  tag legacy: ['SV-43176', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
