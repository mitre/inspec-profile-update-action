control 'SV-224576' do
  title 'BMC CONTROL-M is not properly defined to the Facility Matrix Table for Top Secret.'
  desc 'Improperly defined security controls for the BMC CONTROL-M could result in the compromise of the network, operating system, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-       TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values
-       TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup

Ensure the BMC CONTROL-M Facility Matrix table is defined as follows:

FAC(USERxx=NAME=CONTROLM,PGM=CTM,ID=nn,ACTIVE,SHRPRF)
FAC(CONTROLM=ASUBM,NOABEND,MULTIUSER,NOXDEF,SIGN(S))
FAC(CONTROLM=RES,LUMSG,STMSG,WARNPW,NORNDPW)
FAC(CONTROLM=NOAUDIT,NOTSOC,MODE=FAIL)
FAC(CONTROLM=LOG(SMF,INIT,MSG,SEC9),UIDACID=8,LOCKTIME=000)'
  desc 'fix', 'The BMC CONTROL-M system programmer and the IAO will ensure that the TOP SECRET Facility Matrix Table is properly defined using the following example:

CONTROLM:
FAC(USERxx=NAME=CONTROLM,PGM=CTM,ID=nn,ACTIVE,SHRPRF)
FAC(CONTROLM=ASUBM,NOABEND,MULTIUSER,NOXDEF)
FAC(CONTROLM=LUMSG,STMSG,SIGN(S),WARNPW,NORNDPW)
FAC(CONTROLM=NOAUDIT,NOTSOC,MODE=FAIL)
FAC(CONTROLM=LOG(SMF,INIT,MSG,SEC9),UIDACID=8,LOCKTIME=000)'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for TSS'
  tag check_id: 'C-26259r518791_chk'
  tag severity: 'medium'
  tag gid: 'V-224576'
  tag rid: 'SV-224576r518793_rule'
  tag stig_id: 'ZCTMT036'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26247r518792_fix'
  tag 'documentable'
  tag legacy: ['SV-32051', 'V-17469']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
