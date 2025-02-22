control 'SV-225586' do
  title 'NetView is not properly defined to the Facility Matrix Table for Top Secret.'
  desc 'Improperly defined security controls for the Product could result in the compromise of the network, operating system, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values
-	TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup

b)	If NETVIEW is properly defined in the Facility Matrix table, there is NO FINDING:

c)	If NETVIEW is improperly defined in the Facility Matrix table, this is a FINDING.'
  desc 'fix', 'Define NETVIEW as a Facility to TOP SECRET in the Facility Matrix Table using the following example:

**** NETVIEW
* 
FACILITY(USERxx=NAME=NETVIEW) 
FACILITY(NETVIEW=MODE=FAIL) 
FACILITY(NETVIEW=PGM=DSI) 
FACILITY(NETVIEW=ACTIVE,SHRPRF,ASUBM,ABEND,MULTIUSER,NOXDEF)
FACILITY(NETVIEW=LUMSG,STMSG,SIGN(M),INSTDATA,NORNDPW,AUTHINIT)

FACILITY(NETVIEW=NOPROMPT,NOAUDIT,RES,WARNPW,NOTSOC,LCFTRANS,IJU)

FACILITY(NETVIEW=MSGLC,NOTRACE,NOEODINIT,NODORMPW,NONPWR)

FACILITY(NETVIEW=LOG(INIT,SMF,MSG,SEC9))

FACILITY(NETVIEW=DOWN=GLOBAL,LOCKTIME=00,DEFACID(*NONE*))'
  impact 0.5
  ref 'DPMS Target zOS NetView for TSS'
  tag check_id: 'C-27285r472554_chk'
  tag severity: 'medium'
  tag gid: 'V-225586'
  tag rid: 'SV-225586r472556_rule'
  tag stig_id: 'ZNETT036'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27273r472555_fix'
  tag 'documentable'
  tag legacy: ['SV-28465', 'V-17469']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
