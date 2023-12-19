control 'SV-224655' do
  title 'CL/SuperSession is not properly defined to the Facility Matrix Table for Top Secret.'
  desc 'Improperly defined security controls for the Product could result in the compromise of the network, operating system, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values
-	TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup

b)	If KLS is properly defined in the Facility Matrix table, there is NO FINDING:

c)	If KLS is improperly defined in the Facility Matrix table, this is a FINDING.'
  desc 'fix', 'Define the CT/Engine started task name KLS as a Facility to TOP SECRET in the Facility Matrix Table using the following example:

*KLS	CL/SUPERSESSION
FACILITY(USERxx=NAME=KLS)
FACILITY(KLS=MODE=FAIL,ACTIVE,SHRPRF)
FACILITY(KLS=PGM=KLV,NOASUBM,NOABEND,NOXDEF)
FACILITY(KLS=ID=xx,MULTIUSER,RES,LUMSG,STMSG,WARNPW,SIGN(M))
FACILITY(KLS=NOINSTDATA,NORNDPW,AUTHINIT,NOPROMPT,NOAUDIT)
FACILITY(KLS=NOTSOC,LOG(INIT,SMF,MSG,SEC9))'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for TSS'
  tag check_id: 'C-26338r519782_chk'
  tag severity: 'medium'
  tag gid: 'V-224655'
  tag rid: 'SV-224655r519784_rule'
  tag stig_id: 'ZCLST036'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26326r519783_fix'
  tag 'documentable'
  tag legacy: ['V-17469', 'SV-27240']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
