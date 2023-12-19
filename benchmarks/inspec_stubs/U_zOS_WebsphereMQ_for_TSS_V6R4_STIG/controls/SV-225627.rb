control 'SV-225627' do
  title 'WebSphere MQ started tasks are not defined in accordance with the proper security requirements.'
  desc 'Started tasks are used to execute WebSphere MQ queue manager services.  Improperly defined WebSphere MQ started tasks may result in inappropriate access to application resources and the loss of accountability.  This exposure could compromise the availability of some system services and application data.'
  desc 'check', 'Refer to the following reports produced by the TSS Data Collection:

-	TSSCMDS.RPT(#STC)
-	TSSCMDS.RPT(@ACIDS)
-	TSSCMDS.RPT(FACLIST) - Preferred report containing all control option values in effect including default values.
-	TSSCMDS.RPT(TSSPRMFL) - Alternate report containing only control option values explicitly coded at TSS startup.

NOTE:	The FACLIST report must be created by security personnel.  The TSSPRMFL report can be used if security personnel have not executed the required steps documented in the TSS Data Collection.

Provide a list of all WebSphere MQ Subsystem Ids (Queue managers) and Release levels.

Review WebSphere MQ started tasks and ensure the following items are in effect:

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).
ssidMSTR is the name of a queue manager STC.
ssidCHIN is the name of a distributed queuing (a.k.a., channel initiator) STC.

1)	Each ssidMSTR and ssidCHIN started task is associated with a unique ACID.
2)	Each ssidMSTR and ssidCHIN started task is defined to the STC record with a unique ACID.
3)	Each ssidMSTR started task ACID has a corresponding WebSphere MQ MASTFAC defined.
4)	WebSphere MQ queue manager facilities is defined to the Facility Matrix Table using the following sample commands:

FAC(USERxx=NAME=ssidMSTR,MODE=FAIL,PGM=CSQ,ID=xx,ACTIVE)
FAC(ssidMSTR=SHRPRF,ASUBM,NOABEND,MULTUSER,XDEF,LUMSG)
FAC(ssidMSTR=STMSG,SIGN(S),INSTDATA,NORNDPW,AUTHINIT)
FAC(ssidMSTR=NOPROMPT,NOAUDIT,RES,WARNPW,NOTSOC)
FAC(ssidMSTR=LCFTRANS,IJU,MSGLC,NOTRACE,NOEODINIT)
FAC(ssidMSTR=NODORMPW,NONPWR)
FAC(ssidMSTR=LOG(INIT,SMF,MSG,SEC9))
FAC(ssidMSTR=DOWN=GLOBAL,LOCKTIME=00,DEFACID=(*NONE*))'
  desc 'fix', 'Review WebSphere MQ started tasks and ensure the following items are in effect:

NOTE: 
           ssid is the queue manager name (a.k.a., subsystem 
             identifier).
           ssidMSTR is the name of a queue manager STC.
           ssidCHIN is the name of a distributed queuing (a.k.a.,  
             channel initiator) STC.

1) Each WebSphere MQ started task is associated with a unique ACID.

2) Each WebSphere MQ started task is defined to the STC record with a unique ACID.

3) Each ssidMSTR STC ACID has a corresponding WebSphere MQ MASTFAC as defined in the z/OS.

i.e. A Started Task Table entry exists for each queue manager started task procedure xxxxMSTR and distributed queuing started task procedure xxxxCHIN.  A corresponding userid for each started task exists.  Queue manager and channel initiator started tasks will not be defined with the BYPASS attribute.

4) WebSphere MQ queue manager facilities are defined using the control options as specified below:

Define each queue manager xxxxMSTR to the TOP SECRET Facility Matrix Table using the following sample commands:

FACILITY(USERxx=NAME=xxxxMSTR)
FACILITY(xxxxMSTR=MODE=FAIL,PGM=CSQ,ID=xx)
FACILITY(xxxxMSTR=ACTIVE,SHRPRF,ASUBM,NOABEND)
FACILITY(xxxxMSTR=MULTUSER,XDEF,LUMSG,STMSG,SIGN(S))
FACILITY(xxxxMSTR=INSTDATA,NORNDPW,AUTHINIT)
FACILITY(xxxxMSTR=NOPROMPT,NOAUDIT,RES,WARNPW)
FACILITY(xxxxMSTR=NOTSOC,LCFTRANS,IJU,MSGLC,NOTRACE)
FACILITY(xxxxMSTR=NOEODINIT,NODORMPW,NONPWR)
(INIT,SMF,MSG,SEC9))
FACILITY(xxxxMSTR=DOWN=GLOBAL,LOCKTIME=00,DEFACID=(*NONE*))'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27328r472683_chk'
  tag severity: 'medium'
  tag gid: 'V-225627'
  tag rid: 'SV-225627r472685_rule'
  tag stig_id: 'ZWMQ0030'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-27316r472684_fix'
  tag 'documentable'
  tag legacy: ['SV-7527', 'V-3904']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
