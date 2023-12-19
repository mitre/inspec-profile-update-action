control 'SV-223529' do
  title 'IBM z/OS JESSPOOL resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ACF command screen enter:
SET CONTROL(GSO)
LIST LIKE(CLASMAP-) {to determine the resource class for JESSPOOL}

NOTE: If CLASMAP defines JESSPOOL as anything other than TYPE(SPL), replace SPL below with the appropriate three letters.

SET RESOURCE(SPL)
LIST LIKE(-)

If the following resources are defined to the JESSPOOL resource class (i.e., TYPE(SPL)) with a default access of PREVENT, this is not a finding.

localnodeid.-
localnodeid.JES2.$TRCLOG.taskid.-.JESTRACE
localnodeid.+MASTER+.SYSLOG.jobid.-.SYSLOG

These resource rules may be more generic as long as they pertain directly to the JESTRACE and SYSLOG data sets. For example:
localnodeid.JES2.-.-.-.JESTRACE
localnodeid.+MASTER+.-.-.-.-

Review the JES2 parameters to determine the localnodeid by searching for OWNNODE in the NJEDEF statement, and then searching for NODE(nnnn) (where nnnn is the value specified by OWNNODE). The NAME parameter value specified on this NODE statement is the localnodeid.

If the following resource is defined to the JESSPOOL resource class (i.e., TYPE(SPL)) with a default access of READ, this is not a finding.
localnodeid.jesid.$JESNEWS.taskid.Dnewslvl.JESNEWS
jesid The logonid associated with your JES2 system.

NOTE: This resource rule may be more generic as long as it pertains directly to the JESNEWS data set. For example:
localnodeid.jesid.$JESNEWS.-.-.JESNEWS'
  desc 'fix', 'NOTE: If CLASMAP defines JESSPOOL as anything other than TYPE(SPL), replace SPL below with the appropriate three letters.

Configure the CLASMAP record to define the JESSPOOL resource class.

Example:
SHOW CLASMAP

The following resources are defined to the JESSPOOL resource class (i.e., TYPE(SPL)) with a default access of PREVENT:
localnodeid.-
localnodeid.JES2.$TRCLOG.taskid.-.JESTRACE
localnodeid.+MASTER+.SYSLOG.jobid.-.SYSLOG

Example:
$KEY(localnodeid) TYPE(SPL)
- UID(*) PREVENT

These resource rules may be more generic as long as they pertain directly to the JESTRACE and SYSLOG data sets. For example:
localnodeid.JES2.-.-.-.JESTRACE
localnodeid.+MASTER+.-.-.-.-

Review the JES2 parameters to determine the localnodeid by searching for OWNNODE in the NJEDEF statement, and then searching for NODE(nnnn) (where nnnn is the value specified by OWNNODE). The NAME parameter value specified on this NODE statement is the localnodeid.

The following resource is defined to the JESSPOOL resource class (i.e., TYPE(SPL)) with a default access of READ:
localnodeid.jesid.$JESNEWS.taskid.Dnewslvl.JESNEWS

jesid The logonid associated with your JES2 system.

This resource rule may be more generic as long as it pertains directly to the JESNEWS data set. For example:
localnodeid.jesid.$JESNEWS.-.-.JESNEWS'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25202r504642_chk'
  tag severity: 'medium'
  tag gid: 'V-223529'
  tag rid: 'SV-223529r533198_rule'
  tag stig_id: 'ACF2-JS-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25190r504643_fix'
  tag 'documentable'
  tag legacy: ['V-97763', 'SV-106867']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
