control 'SV-225597' do
  title 'Quest NC-Pass will be properly defined to the Facility Matrix Table.'
  desc 'Improperly defined security controls for Quest NC-Pass could result in the compromise of the network, operating system, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values
-	TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup

If the Quest NC-Pass Facility Matrix table is defined as stated below, this is not a finding.

FACILITY DISPLAY FOR NCPASS
INITPGM=NCS      ID=14 TYPE=099
ATTRIBUTES=IN-USE,ACTIVE,SHRPRF,NOASUBM,NOABEND,MULTIUSER,NOXDEF
ATTRIBUTES=LUMSG,STMSG,SIGN(M),INSTDATA,NORNDPW,AUTHINIT
ATTRIBUTES=NOPROMPT,NOAUDIT,RES,WARNPW,NOTSOC,LCFTRANS
ATTRIBUTES=MSGLC,NOTRACE,NOEODINIT,IJU,NODORMPW,NONPWR
ATTRIBUTES=LUUPD
MODE=FAIL  DOWN=GLOBAL  LOGGING=INIT,SMF,MSG,SEC9
UIDACID=8 LOCKTIME=000 DEFACID=*NONE*   KEY=8
MAXUSER=03000  PRFT=003'
  desc 'fix', 'The IAO working with the systems programmer will ensure the Facility Matrix Table for Quest NC-Pass is proper defined using the following example:

*****NCPASS
FAC(USERxx=NAME=NCPASS,PGM=NCS,ID=nn,ACTIVE,NOASUBM)
FAC(NCPASS=LUMSG,STMSG,NORNDPW,WARNPW,MODE=FAIL)
FAC(NCPASS=LOG(SMF,INIT,MSG,SEC9),UIDACID=8,LOCKTIME=000)'
  impact 0.5
  ref 'DPMS Target zOS Quest NC-Pass for TSS'
  tag check_id: 'C-27297r472590_chk'
  tag severity: 'medium'
  tag gid: 'V-225597'
  tag rid: 'SV-225597r472592_rule'
  tag stig_id: 'ZNCPT036'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27285r472591_fix'
  tag 'documentable'
  tag legacy: ['SV-40877', 'V-17469']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
