control 'SV-224586' do
  title 'BMC CONTROL-D is not properly defined to the Facility Matrix Table for Top Secret.'
  desc 'Improperly defined security controls for the BMC CONTROL-D could result in the compromise of the network, operating system, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-       TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values
-       TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup

Ensure the BMC CONTROL-D Facility Matrix table is defined as follows:

FAC(USERxx=NAME=CONTROLD,PGM=CTD,ID=nn,ACTIVE,SHRPRF)
FAC(CONTROLD=ASUBM,NOABEND,MULTIUSER,NOXDEF,SIGN(S))
FAC(CONTROLD=RES,LUMSG,STMSG,WARNPW,NORNDPW)
FAC(CONTROLD=NOAUDIT,NOTSOC,MODE=FAIL)
FAC(CONTROLD=LOG(SMF,INIT,MSG,SEC9),UIDACID=8,LOCKTIME=000)'
  desc 'fix', 'The BMC CONTROL-D system programmer and the IAO will ensure that the TOP SECRET Facility Matrix Table is proper defined using the following example:

CONTROLD:
FAC(USERxx=NAME=CONTROLD,PGM=CTO,ID=nn,ACTIVE,SHRPRF)
FAC(CONTROLD=ASUBM,NOABEND,MULTIUSER,NOXDEF)
FAC(CONTROLD=LUMSG,STMSG,SIGN(S),WARNPW,NORNDPW)
FAC(CONTROLD=NOAUDIT,RES,NOTSOC,MODE=FAIL)
FAC(CONTROLD=LOG(SMF,INIT,MSG,SEC9),UIDACID=8,LOCKTIME=000)'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-D for TSS'
  tag check_id: 'C-26269r518713_chk'
  tag severity: 'medium'
  tag gid: 'V-224586'
  tag rid: 'SV-224586r518715_rule'
  tag stig_id: 'ZCTDT036'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26257r518714_fix'
  tag 'documentable'
  tag legacy: ['V-17469', 'SV-32053']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
