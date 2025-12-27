control 'SV-224597' do
  title 'BMC CONTROL-O is not properly defined to the Facility Matrix Table for Top Secret.'
  desc 'Improperly defined security controls for the BMC CONTROL-O could result in the compromise of the network, operating system, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-       TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values
-       TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup

Ensure the BMC CONTROL-O Facility Matrix table is defined as follows:

FAC(USERxx=NAME=CONTROLO,PGM=CTO,ID=nn,ACTIVE,SHRPRF)
FAC(CONTROLO=ASUBM,NOABEND,MULTIUSER,NOXDEF,SIGN(S))
FAC(CONTROLO=RES,LUMSG,STMSG,WARNPW,NORNDPW)
FAC(CONTROLO=NOAUDIT,NOTSOC,MODE=FAIL)
FAC(CONTROLO=LOG(SMF,INIT,MSG,SEC9),UIDACID=8,LOCKTIME=000)'
  desc 'fix', 'The BMC CONTROL-O system programmer and the IAO will ensure that the TOP SECRET Facility Matrix Table is proper defined using the following example:

CONTROLO:
FAC(USERxx=NAME=CONTROLO,PGM=CTO,ID=nn,ACTIVE,SHRPRF)
FAC(CONTROLO=ASUBM,NOABEND,MULTIUSER,NOXDEF)
FAC(CONTROLO=LUMSG,STMSG,SIGN(S),WARNPW,NORNDPW)
FAC(CONTROLO=NOAUDIT,RES,NOTSOC,MODE=FAIL)
FAC(CONTROLO=LOG(SMF,INIT,MSG,SEC9),UIDACID=8,LOCKTIME=000)'
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-O for TSS'
  tag check_id: 'C-26280r518884_chk'
  tag severity: 'medium'
  tag gid: 'V-224597'
  tag rid: 'SV-224597r518886_rule'
  tag stig_id: 'ZCTOT036'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26268r518885_fix'
  tag 'documentable'
  tag legacy: ['V-17469', 'SV-32052']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
