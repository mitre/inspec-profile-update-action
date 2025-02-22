control 'SV-223528' do
  title 'IBM z/OS JESTRACE and/or SYSLOG resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ACF command screen enter:
Set RESOURCE(SPL)
List like(localnodeid-)

If the following resources in the JESSPOOL resource class (i.e., TYPE(SPL)) are configured as noted below, this is not a finding.

localnodeid.JES2.$TRCLOG.taskid.-.JESTRACE
localnodeid.+MASTER+.SYSLOG.jobid.-.SYSLOG or
localnodeid.+BYPASS+.SYSLOG.jobid.-.SYSLOG

NOTE: These resource rules may be more generic as long as they pertain directly to the JESTRACE and SYSLOG data sets. For example:
localnodeid.JES2.-.-.-.JESTRACE
localnodeid.+MASTER+.-.-.-.SYSLOG or
localnodeid.+BYPASS+.-.-.-.SYSLOG

NOTE: To determine the localnodeid by searching for OWNNODE in the NJEDEF statement, and then searching for NODE(nnnn) (where nnnn is the value specified by OWNNODE). The NAME parameter value specified on this NODE statement is the localnodeid. Another method is to issue the JES2 command $D NODE,NAME,OWNNODE=YES to obtain the NAME of the OWNNODE.

If access authorization for the resources mentioned above is restricted to the following, this is not a finding.

Logonid(s) associated with external writer(s) can have complete access.

NOTE: An external writer is an STC that removes data sets from the JES spool. In this case, it is responsible for archiving the JESTRACE and SYSLOG data sets. The STC default name is XWTR and the external writer program is called IASXWR00.

Systems personnel and security administrators responsible for diagnosing JES2 and z/OS problems can have complete access.

Application Development and Application Support personnel responsible for diagnosing application problems can have READ access to the SYSLOG resource.'
  desc 'fix', 'NOTE: If CLASMAP defines JESSPOOL as anything other than TYPE(SPL), replace SPL below with the appropriate three letters.

Configure the following resources in the JESSPOOL resource class (i.e., TYPE(SPL)):

localnodeid.JES2.$TRCLOG.taskid.-.JESTRACE
localnodeid.+MASTER+.SYSLOG.jobid.-.SYSLOG or
localnodeid.+BYPASS+.SYSLOG.jobid.-.SYSLOG

NOTE: These resource rules may be more generic as long as they pertain directly to the JESTRACE and SYSLOG data sets. For example:
localnodeid.JES2.-.-.-.JESTRACE
localnodeid.+MASTER+.-.-.-.- or
localnodeid.+BYPASS+.-.-.-.-

NOTE: To determine the localnodeid by searching for OWNNODE in the NJEDEF statement, and then searching for NODE(nnnn) (where nnnn is the value specified by OWNNODE). The NAME parameter value specified on this NODE statement is the localnodeid. Another method is to issue the JES2 command $D NODE,NAME,OWNNODE=YES to obtain the NAME of the OWNNODE.

Configure access authorization for the resources mentioned above is restricted to the following:

Logonid(s) associated with external writer(s) can have complete access.

NOTE: An external writer is a STC that removes data sets from the JES spool. In this case, it is responsible for archiving the JESTRACE and SYSLOG data sets. The STC default name is XWTR and the external writer program is called IASXWR00.

Systems personnel and security administrators responsible for diagnosing JES2 and z/OS problems can have complete access.

Application Development and Application Support personnel responsible for diagnosing application problems can have READ access to the SYSLOG resource.

Example:
SET R(SPL)
$KEY(localnodeid) TYPE(SPL)
-.SYSLOG.-.-.- UID(sysprgmr) ALLOW
-.SYSLOG.-.-.- UID(seca) ALLOW
-.SYSLOG.-.-.- UID(appdudt) SERVICE(READ) ALLOW
-.SYSLOG.-.-.- UID(apps) SERVICE(READ) ALLOW
-.$TRCLOG.-.-.- UID(sysprgmr) ALLOW
-.$TRCLOG.-.-.- UID(seca) ALLOW
- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25201r504639_chk'
  tag severity: 'medium'
  tag gid: 'V-223528'
  tag rid: 'SV-223528r533198_rule'
  tag stig_id: 'ACF2-JS-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25189r504640_fix'
  tag 'documentable'
  tag legacy: ['V-97761', 'SV-106865']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
