control 'SV-223993' do
  title 'IBM z/OS JESTRACE and/or SYSLOG resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS JESSPOOL(*)

If JESSPOOL localnodeid resource is not defined, this is a finding.

Enter
TSS WHOHAS JESSPOOL(localnodeid.)
Review the following resources defined to the JESSPOOL resource class:

localnodeid.JES2.$TRCLOG.taskid.*.JESTRACE
localnodeid.+MASTER+.SYSLOG.jobid.*.SYSLOG or
localnodeid.+BYPASS+.SYSLOG.jobid.-.SYSLOG

NOTE: These resource profiles may be more generic as long as they pertain directly to the JESTRACE and SYSLOG data sets. For example:

localnodeid.JES2.*.*.*.JESTRACE
localnodeid.+MASTER+.*.*.*.SYSLOG or
localnodeid.+BYPASS+.*.*.*.SYSLOG

NOTE: Review the JES2 parameters to determine the localnodeid by searching for OWNNODE in the NJEDEF statement, and then searching for NODE(nnnn) (where nnnn is the value specified by OWNNODE). The NAME parameter value specified on this NODE statement is the localnodeid. Another method is to issue the JES2 command $D NODE,NAME,OWNNODE=YES to obtain the NAME of the OWNNODE.

If the access authorization for the resources mentioned above is restricted to the following, this is not a finding.

-ACID(s) associated with external writer(s) can have complete access.

NOTE: An external writer is an STC that removes data sets from the JES spool. In this case, it is responsible for archiving the JESTRACE and SYSLOG data sets. The STC default name is XWTR and the external writer program is called IASXWR00.

-Systems personnel and security administrators responsible for diagnosing JES2 and z/OS problems can have complete access.

-Application Development and Application Support personnel responsible for diagnosing application problems can have READ access to the SYSLOG resource.'
  desc 'fix', 'Configure the access authorization for resources defined to the JESTRACE and SYSLOG resources in the JESSPOOL resource class to be restricted to the appropriate personnel.

Review the following resources defined to the JESSPOOL resource class:

localnodeid.JES2.$TRCLOG.taskid.*.JESTRACE
localnodeid.+MASTER+.SYSLOG.jobid.*.SYSLOG or
localnodeid.+BYPASS+.SYSLOG.jobid.*.SYSLOG

NOTE: These resource profiles may be more generic as long as they pertain directly to the JESTRACE and SYSLOG data sets. For example:

localnodeid.JES2.$TRCLOG.
localnodeid.+MASTER+.SYSLOG. or
localnodeid.+BYPASS+.SYSLOG.

NOTE: Review the JES2 parameters to determine the localnodeid by searching for OWNNODE in the NJEDEF statement, and then searching for NODE(nnnn) (where nnnn is the value specified by OWNNODE). The NAME parameter value specified on this NODE statement is the localnodeid. Another method is to issue the JES2 command $D NODE,NAME,OWNNODE=YES to obtain the NAME of the OWNNODE.

Ensure that access authorization for the resources mentioned above is restricted to the following:

-ACID(s) associated with external writer(s) can have complete access.

NOTE: An external writer is a STC that removes data sets from the JES spool. In this case, it is responsible for archiving the JESTRACE and SYSLOG data sets. The STC default name is XWTR and the external writer program is called IASXWR00.

-Systems personnel and security administrators responsible for diagnosing JES2 and z/OS problems can have complete access.

-Application Development and Application Support personnel responsible for diagnosing application problems can have READ access to the SYSLOG resource.

For Example:

TSS ADD(dept-acid) JESSPOOL(localnodeid)

TSS PERMIT(<syspsmpl>) JESSPOOL(localnodeid.JES2.$TRCLOG.) ACCESS(ALL)
TSS PERMIT(<secasmpl>) JESSPOOL(localnodeid.JES2.$TRCLOG.) ACCESS(ALL)

TSS PERMIT(<syspsmpl>) JESSPOOL(localnodeid.+MASTER+.SYSLOG.) ACCESS(ALL)
TSS PERMIT(<secasmpl>) JESSPOOL(localnodeid.+MASTER+.SYSLOG.) ACCESS(ALL)
TSS PERMIT(<appdsmpl>) JESSPOOL(localnodeid.+MASTER+.SYSLOG.) ACCESS(READ)
TSS PERMIT(<appssmpl>) JESSPOOL(localnodeid.+MASTER+.SYSLOG.) ACCESS(READ)
or
TSS PERMIT(<syspsmpl>) JESSPOOL(localnodeid.+BYPASS+.SYSLOG.) ACCESS(ALL)
TSS PERMIT(<secasmpl>) JESSPOOL(localnodeid.+BYPASS+.SYSLOG.) ACCESS(ALL)
TSS PERMIT(<appdsmpl>) JESSPOOL(localnodeid.+BYPASS+.SYSLOG.) ACCESS(READ)
TSS PERMIT(<appssmpl>) JESSPOOL(localnodeid.+BYPASS+.SYSLOG.) ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25666r516378_chk'
  tag severity: 'medium'
  tag gid: 'V-223993'
  tag rid: 'SV-223993r877834_rule'
  tag stig_id: 'TSS0-JS-000090'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25654r516379_fix'
  tag 'documentable'
  tag legacy: ['SV-107797', 'V-98693']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
