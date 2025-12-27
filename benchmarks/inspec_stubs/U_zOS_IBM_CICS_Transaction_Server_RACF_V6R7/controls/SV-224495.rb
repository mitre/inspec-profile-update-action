control 'SV-224495' do
  title 'CICS region logonid(s) must be defined and/or controlled in accordance with the security requirements.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Improperly defined or controlled CICS region userids may provide an exposure and vulnerability within the CICS environment.  This could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.

The region userid should be associated with a unique RACF userid.'
  desc 'check', 'a)	Refer to the following report produced by the z/OS Data Collection:

-	EXAM.RPT(CICSPROC)

Refer to the following reports produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)
-	DSMON.RPT(RACCDT)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)	Ensure that the following is defined for each CICS region:

1)	A unique userid is defined.
2)	Defined to the STARTED resource class.

c)	If (b) is true, this is not a finding.

d)	If (b) is untrue, this is a finding.'
  desc 'fix', "Review all CICS region, default, and end-user userids to ensure they are defined and controlled as required.

Ensure that the following is defined for each CICS region:

1)	A unique userid is defined.

Use the RACF Adduser command to accomplish this.  A sample command is provided here:

AU <cicsregionid> NAME('STC, CICS Region') DFLTGRP(STC) OWNER(STC) 

2)	Defined to the STARTED resource class.

Use the RACF RDEFINE command.  A sample is provided here:

RDEF STARTED <cicsprocname>.** UACC(NONE) OWNER(ADMIN) DATA('USED TO MAP <cicsprocname> TO A VALID RACF USERID') STDATA(USER(=MEMBER) GROUP(STC) TRACE(YES))"
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for RACF'
  tag check_id: 'C-26178r520271_chk'
  tag severity: 'medium'
  tag gid: 'V-224495'
  tag rid: 'SV-224495r520273_rule'
  tag stig_id: 'ZCIC0040'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26166r520272_fix'
  tag 'documentable'
  tag legacy: ['SV-7532', 'V-44']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
