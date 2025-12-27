control 'SV-223534' do
  title 'IBM z/OS JES2 output devices must be controlled in accordance with the proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ACF input screen enter:
SET CONTROL(GSO)
LIST LIKE(CLASMAP-) [To determine the resource class for WRITER]

NOTE: If CLASMAP defines WRITER as anything other than TYPE(WTR), replace WTR below with the appropriate three letters.

SET RESOURCE(WTR)
LIST LIKE(-)

If the JES2.- resource is defined to the WRITER resource class with a default access of PREVENT, this is not a finding.

If the other resources mentioned below are protected by generic and/or fully qualified rules defined to the WRITER resource class with a default access of PREVENT, this is not a finding.

If the ACF2 resources and/or generic equivalent identified below are defined with access restricted to the appropriate personnel, this is not a finding.

NOTE: A default access of READ is allowed for output destinations that are permitted to route output for all users. Currently, there is no guidance on which output destinations are appropriate for a default access of READ. However, common sense should prevail during the analysis. For example, a default access of READ would typically be inappropriate for RJE, NJE, and offload output destinations.

JES2 is typically the name of the JES2 subsystem. Refer to the SUBSYS report and locate the entry with the description of PRIMARY JOB ENTRY SUBSYSTEM. The SUBSYSTEM NAME of this entry is the name of the JES2 subsystem.

OFFn, where n is the number of the offload transmitter. Determine the numbers by searching for OFF( in the JES2 parameters.

PRTn, where n is the number of the local printer. Determine the numbers by searching for PRT( in the JES2 parameters.

PUNn, where n is the number of the local card punch. Determine the numbers by searching for PUN( in the JES2 parameters.

Nodename is the NAME parameter value specified on the NODE statement. Review the JES2 parameters for NJE node definitions by searching for NODE( in the report.

Rnnnn.PRm, where nnnn is the number of the remote workstation and m is the number of the printer. Determine the numbers by searching for .PR in the JES2 parameters.

Rnnnn.PUm, where nnnn is the number of the remote workstation and m is the number of the punch. Determine the numbers by searching for .PU in the JES2 parameters.'
  desc 'fix', 'NOTE: If CLASMAP defines WRITER as anything other than TYPE(WTR), replace WTR below with the appropriate three letters.

Configure the WRITER resource class (i.e., TYPE(WTR)) as follows with:

JES2.- (backstop profile)
JES2.LOCAL.OFFn.- (spool offload transmitter)
JES2.LOCAL.OFFn.ST (spool offload SYSOUT transmitter)
JES2.LOCAL.OFFn.JT (spool offload job transmitter)
JES2.LOCAL.PRTn (local printer)
JES2.LOCAL.PUNn (local punch)
JES2.NJE.nodename (NJE node)
JES2.RJE.Rnnnn.PRm (remote printer)
JES2.RJE.Rnnnn.PUm (remote punch)

Ensure the following items are in effect: 

The JES2.- resource is defined to the WRITER resource class with a default access of PREVENT.

The other resources mentioned above are protected by generic and/or fully qualified rules defined to the WRITER resource class with a default access of PREVENT.

NOTE: A default access of READ is allowed for output destinations that are permitted to route output for all users. Currently, there is no guidance on which output destinations are appropriate for a default access of READ. However, common sense should prevail during the analysis. For example, a default access of READ would typically be inappropriate for RJE, NJE, and offload output destinations.

Examples:
$KEY(JES2) TYPE(WTR) 
LOCAL.OFF- UID(*) PREVENT 
LOCAL.OFF-.JT UID(*) PREVENT
LOCAL.OFF-.ST UID(oper) SERVICE(READ) ALLOW
LOCAL.OFF-.ST UID(sysprgmr) SERVICE(READ) ALLOW
LOCAL.OFF-.ST UID(seca) SERVICE(READ) ALLOW
LOCAL.OFF-.ST UID(*) PREVENT 
LOCAL.PRT- UID(*) SERVICE(READ) ALLOW
LOCAL.PUN- UID(*) PREVENT 
NJE.- UID(*) SERVICE(READ) ALLOW
RJE.- UID(sysprgmr) SERVICE(READ) ALLOW 
RJE.- UID(*) PREVENT 
- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25207r504657_chk'
  tag severity: 'medium'
  tag gid: 'V-223534'
  tag rid: 'SV-223534r533198_rule'
  tag stig_id: 'ACF2-JS-000070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25195r504658_fix'
  tag 'documentable'
  tag legacy: ['SV-106877', 'V-97773']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
