control 'SV-225610' do
  title 'Tivoli Asset Discovery for z/OS (TADz) Started Task name(s) must be properly identified / defined to the system ACP.'
  desc 'Tivoli Asset Discovery for z/OS (TADz) requires a started task(s) that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system Access Control Program (ACP), it allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'Refer to the following reports produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACIDS)

Review each TADz STC/Batch ACID(s) for the following:

___	Is defined with Facility of STC and/or BATCH.

___	Is sourced to the INTRDR.

If all of the above are true, there is NO FINDING.

If any of the above is untrue, this is a FINDING.'
  desc 'fix', "The TADz Systems Programmer and ISSO will ensure that the started task(s) for TADz is properly defined.

Define the started task for TADz.

Example:

TSS CRE(TADZMON) DEPT(Dept) NAME('TADz STC') -
FAC(STC) PASSWORD(password,0) -
SOURCE(INTRDR)"
  impact 0.5
  ref 'DPMS Target zOS TADz for TSS'
  tag check_id: 'C-27310r472629_chk'
  tag severity: 'medium'
  tag gid: 'V-225610'
  tag rid: 'SV-225610r472631_rule'
  tag stig_id: 'ZTADT030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27298r472630_fix'
  tag 'documentable'
  tag legacy: ['V-17452', 'SV-28555']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
