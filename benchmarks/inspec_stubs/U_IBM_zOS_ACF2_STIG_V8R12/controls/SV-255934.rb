control 'SV-255934' do
  title 'IBM Integrated Crypto Service Facility (ICSF) Started Task name must be properly identified / defined to the system ACP.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) requires a started task that will be restricted to certain resources, datasets and other system functions. By defining the started task as a userid to the system ACP, It allows the ACP to control the access and authorized users that require these capabilities. Failure to properly control these capabilities, could compromise of the operating system environment, ACP, and customer data.'
  desc 'check', 'From the ACF command screen enter:
SET LID 
SET VERBOSE 
LIST IF(MUSASS)
LIST IF(STC)

If the logonid for the IBM Integrated Crypto Service Facility (ICSF) started task does not include MUSASS and/or NO-SMC, this is a finding.'
  desc 'fix', 'Ensure that the started task for IBM Integrated Crypto Service Facility (ICSF) Started Task(s) is properly Identified / defined to the System ACP.

If the product requires a Started Task, verify that it is properly defined to the System ACP with the proper attributes.

Most installation manuals will indicate how the Started Task is identified and any additional attributes that must be specified.  Define the started task userid CSFSTART for IBM Integrated Crypto Service Facility (ICSF).

Example:

INSERT CSFSTART NAME(STC, ICSF) NO-SMC STC'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-59611r881292_chk'
  tag severity: 'medium'
  tag gid: 'V-255934'
  tag rid: 'SV-255934r881294_rule'
  tag stig_id: 'ACF2-IC-000040'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-59554r881293_fix'
  tag 'documentable'
  tag legacy: ['SV-30578', 'V-17452']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
