control 'SV-224428' do
  title 'BMC Mainview for z/OS Resource Class will be defined or active in the ACP.'
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', 'Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(SETROPTS)
-	DSMON.RPT(RACCDT) - Alternate list of active resource classes

Automated Analysis
Refer to the following report produced by the RACF Data Collection:

-	PDI(ZMVZ0038)

Ensure that the BMC Mainview for z/OS resource class(es) is (are) defined and active.'
  desc 'fix', 'The IAO will ensure that the BMC Mainview for z/OS Resource Class(es) is (are) active.

Use the following commands as an example:

RDEFINE CDT class -
CDTINFO( MAXLENGTH(64) DEFAULTUACC(NONE) -
FIRST(ALPHA) CASE(UPPER) -
OTHER(ALPHA,NUMERIC,NATIONAL,SPECIAL) -
POSIT(301) RACLIST(REQUIRED) -
GENERIC(ALLOWED) GENLIST(ALLOWED) -
OPERATIONS(YES) -
) UACC(NONE)

SETROPTS CLASSACT(CDT) RACLIST(CDT)
SETROPTS RACLIST(CDT) REFRESH

SETROPTS GENERIC(class) GENCMD(class)
SETROPTS CLASSACT(class) RACLIST(class)
SETROPTS RACLIST(class) REFRESH'
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for RACF'
  tag check_id: 'C-26105r518992_chk'
  tag severity: 'medium'
  tag gid: 'V-224428'
  tag rid: 'SV-224428r855095_rule'
  tag stig_id: 'ZMVZR038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-26093r518993_fix'
  tag 'documentable'
  tag legacy: ['V-18011', 'SV-33845']
  tag cci: ['CCI-000336', 'CCI-002358']
  tag nist: ['CM-4 (2)', 'AC-25']
end
