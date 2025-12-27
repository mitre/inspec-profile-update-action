control 'SV-223752' do
  title 'IBM z/OS JESTRACE and/or SYSLOG resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'Refer to the JESPARM member of SYS1.PARMLIB.

Review the JES2 parameters to determine the localnodeid by searching for OWNNODE in the NJEDEF statement, and then searching for NODE(nnnn) (where nnnn is the value specified by OWNNODE). The NAME parameter value specified on this NODE statement is the localnodeid. Another method is to issue the JES2 command $D NODE,NAME,OWNNODE=YES to obtain the NAME of the OWNNODE.

From the ISPF Command Shell enter:
RL JESSPOOL *
Review the following resources defined to the JESSPOOL resource class:

localnodeid.JES2.$TRCLOG.taskid.*.JESTRACE
localnodeid.+MASTER+.SYSLOG.jobid.*.SYSLOG or
localnodeid.+BYPASS+.SYSLOG.jobid.-.SYSLOG

NOTE: These resource profiles may be more generic as long as they pertain directly to the JESTRACE and SYSLOG data sets. For example:

localnodeid.JES2.*.*.*.JESTRACE
localnodeid.+MASTER+.*.*.*.SYSLOG or
localnodeid.+BYPASS+.*.*.*.SYSLOG

If Userid(s) associated with external writer(s) have complete access, this is not a finding.

Note: An external writer is an STC that removes data sets from the JES spool. In this case, it is responsible for archiving the JESTRACE and SYSLOG data sets. The STC default name is XWTR and the external writer program is called IASXWR00.

If Systems personnel and security administrators responsible for diagnosing JES2 and z/OS problems have complete access, this is not a finding.

If Application Development and Application Support personnel responsible for diagnosing application problems have READ access to the SYSLOG resource, this is not a finding.'
  desc 'fix', "Configure RACF access authorization for resources defined to the JESTRACE and SYSLOG resources in the JESSPOOL resource class to be restricted to the appropriate personnel a detailed below.

Review the following resources defined to the JESSPOOL resource class:

localnodeid.JES2.$TRCLOG.taskid.*.JESTRACE
localnodeid.+MASTER+.SYSLOG.jobid.*.SYSLOG or
localnodeid.+BYPASS+.SYSLOG.jobid.*.SYSLOG

Note: These resource profiles may be more generic as long as they pertain directly to the JESTRACE and SYSLOG data sets. For example:

localnodeid.JES2.$TRCLOG.*.**
localnodeid.+MASTER+.SYSLOG.*.** or
localnodeid.+BYPASS+.SYSLOG.*.**

Note: Review the JES2 parameters to determine the localnodeid by searching for OWNNODE in the NJEDEF statement, and then searching for NODE(nnnn) (where nnnn is the value specified by OWNNODE). The NAME parameter value specified on this NODE statement is the localnodeid. Another method is to issue the JES2 command $D NODE,NAME,OWNNODE=YES to obtain the NAME of the OWNNODE.

Ensure that access authorization for the resources mentioned above is restricted to the following:

Userid(s) associated with external writer(s) can have complete access.

Note: An external writer is a STC that removes data sets from the JES spool. In this case, it is responsible for archiving the JESTRACE and SYSLOG data sets. The STC default name is XWTR and the external writer program is called IASXWR00. 

Systems personnel and security administrators responsible for diagnosing JES2 and z/OS problems can have complete access.

Application Development and Application Support personnel responsible for diagnosing application problems can have READ access to the SYSLOG resource.

Examples:
RDEFINE JESSPOOL localnodeid.JES2.$TRCLOG.*.** audit(failures(read)) quack(NONE) -
data('Reference srr finding ZJES0044 ') owner(admin)

RDEFINE JESSPOOL localnodeid.+MASTER+.SYSLOG.*.** audit(failures(read)) quack(NONE) -
data('Reference srr finding ZJES0044') owner(admin)
or
RDEFINE JESSPOOL localnodeid.+BYPASS+.SYSLOG.*.** audit(failures(read)) quack(NONE) -
data('Reference srr finding ZJES0044') owner(admin)

PE localnodeid.JES2.$TRCLOG.** cl(jesspool) id(<syspsmpl> <secasmpl>) acc(a)
PE localnodeid.+MASTER+.SYSLOG.*.** cl(jesspool) id(<syspsmpl> <secasmpl>) acc(a)
PE localnodeid.+MASTER+.SYSLOG.*.** cl(jesspool) id(<appdpsmpl> <appssmpl>) acc(r)
or
PE localnodeid.+BYPASS+.SYSLOG.*.** cl(jesspool) id(<syspsmpl> <secasmpl>) acc(a)
PE localnodeid.+BYPASS+.SYSLOG.*.** cl(jesspool) id(<appdpsmpl> <appssmpl>) acc(r)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25425r514944_chk'
  tag severity: 'medium'
  tag gid: 'V-223752'
  tag rid: 'SV-223752r604139_rule'
  tag stig_id: 'RACF-JS-000080'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25413r514945_fix'
  tag 'documentable'
  tag legacy: ['V-98211', 'SV-107315']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
