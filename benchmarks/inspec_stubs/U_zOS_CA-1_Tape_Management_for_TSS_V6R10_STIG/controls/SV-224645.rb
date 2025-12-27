control 'SV-224645' do
  title 'CA 1 Tape Management will be properly defined to the Facility Matrix Table.'
  desc 'Improperly defined security controls for CA 1 Tape Management could result in the compromise of the network, operating system, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values
-	TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup

If the CA 1 Tape Management Facility Matrix table is defined as stated below, this is not a finding.

FACILITY DISPLAY FOR CA1
INITPGM=TMS id=xx TYPE=099
ATTRIBUTES=IN-USE,ACTIVE,SHRPRF,NOASUBM,NOABEND,MULTIUSER,NOXDEF
ATTRIBUTES=NOLUMSG,NOSTMSG,SIGN(M),INSTDATA,NORNDPW,AUTHINIT
ATTRIBUTES=NOPROMPT,NOAUDIT,RES,NOWARNPW,NOTSOC,LCFCMD
ATTRIBUTES=MSGLC,NOTRACE,NOEODINIT,IJU,NODORMPW,NONPWR
ATTRIBUTES=LUUPD
MODE=FAIL DOWN=GLOBAL LOGGING=INIT,SMF,MSG,SEC9
UIDACID=8 LOCKTIME=000 DEFACID=*NONE* KEY=8
MAXUSER=03000  PRFT=003'
  desc 'fix', 'The IAO working with the systems programmer will ensure the Facility Matrix Table for CA 1 Tape Management is proper defined using the following example:

*****CA1
FAC(USERxx=NAME=CA1,PGM=TMS,ID=nn,ACTIVE,NOASUBM)
FAC(CA1=NOLUMSG,NOSTMSG,NORNDPW,NOWARNPW,MODE=FAIL)
FAC(CA1=LOG(SMF,INIT,MSG,SEC9),UIDACID=8,LOCKTIME=000)'
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for TSS'
  tag check_id: 'C-26328r519539_chk'
  tag severity: 'medium'
  tag gid: 'V-224645'
  tag rid: 'SV-224645r519541_rule'
  tag stig_id: 'ZCA1T036'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26316r519540_fix'
  tag 'documentable'
  tag legacy: ['SV-40631', 'V-17469']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
