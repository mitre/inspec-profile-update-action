control 'SV-223874' do
  title 'CA-TSS Security control ACIDs must be limited to the administrative authorities authorized and that require these privileges to perform their job duties.'
  desc 'The use of security policy filters provides protection for the confidentiality of data by restricting the flow of data. A crucial part of any flow control solution is the ability to configure policy filters. This allows the operating system to enforce multiple and different security policies. Policy filters serve to enact and enforce the organizational policy as it pertains to controlling data flow.'
  desc 'check', 'From the ISPF Command Shell enter:

TSS LIST(ACIDS) DATA(ADMIN, BASIC)

If any ACIDs other than TYPE=CENTRAL (SCA/MSCA) has the following administrative authority, this is a finding.

FACILITIES(ALL)
PROGRAM(ALL)
PROGRAM(OWN)
RESOURCE(ALL)
ROSRES(ALL)
VOLUME(ALL)
VOLUME(OWN)

MISC1(ALL)
MISC1(LCF)
MISC1(LTIME)
MISC1(RDT)
MISC1(USER)

MISC2(ALL)
MISC2(DLF)
MISC2(NDT)
MISC2(SMS)

MISC4(ALL)

MISC8(ALL)
MISC8(LISTAPLU)
MISC8(LISTRDT)
MISC8(LISTSDT)
MISC8(LISTSTC)
MISC8(MCS)

MISC9(ALL)
MISC9(BYPASS)
MISC9(CONSOLE)
MISC9(GLOBAL)
MISC9(MASTFAC)
MISC9(MODE)
MISC9(STC)
MISC9(TRACE)'
  desc 'fix', 'Review all security administrator ACIDs. Evaluate the impact of limiting the amount of excessive administrative authorities. Develop a plan of action and implement the changes.

The following are examples for other types (DCA, VCA, ZCA, LSCA) that require administrative authorities: (note: these are examples and does not mean everyone should have all of these levels).

data set(ALL)ACC(ALL)
data set(XAUTH,OWN,REPORT,AUDIT,INFO)ACC(ALL)
OTRAN(ALL)ACC(ALL)
ACID(ALL)
ACID(INFO,MAINTAIN)
MISC1(INSTDATA,SUSPEND,TSSSIM,NOATS)
MISC2(TSO,TARGET)
MISC8(PWMAINT,REMASUSP)
MISC9(GENERIC)
FACILITY(BATCH, TSO, ROSCOE, CICS, xxxx)

Where ‘xxxx’ is a facility the application security team grants access into for their application users. This must not be STC, CA1, DFHSM, or other "domain level mastfac/facility. This is only for those "onlines" that users truly log into to access their applications/data such as TSO, CICS regions, IDMS, ROSCOE, FTP, etc.

TSS ADMIN(acid)RESOURCE(REPORT,INFO,AUDIT) can be allowed and is required to run TSSUTIL reports.

Note: "RESOURCE" can specify a more specific Resource Class, such as "OTRAN", "data set", "IDMSGON", "PROGRAM" for non SCA/MSCA type of accounts. These administrators will not have "RESOURCE" specified in administrative authority. 

Note: "ALL" will display as "*ALL*" but also means approved for any single administrative authority under that specific item.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25547r516021_chk'
  tag severity: 'high'
  tag gid: 'V-223874'
  tag rid: 'SV-223874r561402_rule'
  tag stig_id: 'TSS0-ES-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25535r516022_fix'
  tag 'documentable'
  tag legacy: ['SV-107559', 'V-98455']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
