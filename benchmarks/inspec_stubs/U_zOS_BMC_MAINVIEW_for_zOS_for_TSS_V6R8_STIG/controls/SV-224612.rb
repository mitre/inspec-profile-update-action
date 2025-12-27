control 'SV-224612' do
  title 'BMC Mainview for z/OS is not properly defined to the Facility Matrix Table for Top Secret.'
  desc 'Improperly defined security controls for BMC Mainview for z/OS could result in the compromise of the network, operating system, and customer data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection:

-       TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values
-       TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup

Ensure the BMC Mainview for z/OS Facility Matrix table is defined as follows:

BBI3:
FAC(USERxx=NAME=BBI3,PGM=BBM,ID=nn,ACTIVE,SHRPRF,ASUBM)
FAC(BBI3=NOABEND,MULTIUSER,NOXDEF,SIGN(S),RES,LUMSG)
FAC(BBI3=STMSG,WARNPW,NORNDPW,NOAUDIT,NOTSOC,MODE=FAIL)
FAC(BBI3=LOG(SMF,INIT,MSG,SEC9),UIDACID=8,LOCKTIME=000)'
  desc 'fix', 'The BMC Mainview for z/OS system programmer and the IAO will ensure that the TOP SECRET Facility Matrix Table is proper defined using the following example:

**** BBI3
* 
FACILITY(USERxx=NAME=BBI3,PGM=BBM,ID=nn,ACTIVE,SHRPRF)
FACILITY(BBI3=ASUBM,NOABEND,MULTIUSER,NOXDEF)
FACILITY(BBI3=LUMSG,STMSG,SIGN(S),NORNDPW)
FACILITY(BBI3=NOAUDIT,RES,WARNPW,NOTSOC)
FACILITY(BBI3=MODE=FAIL,LOG(SMF,INIT,MSG,SEC9))
FACILITY(BBI3=UIDACID=8,LOCKTIME=000)'
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for TSS'
  tag check_id: 'C-26295r519013_chk'
  tag severity: 'medium'
  tag gid: 'V-224612'
  tag rid: 'SV-224612r519015_rule'
  tag stig_id: 'ZMVZT036'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26283r519014_fix'
  tag 'documentable'
  tag legacy: ['V-17469', 'SV-33843']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
