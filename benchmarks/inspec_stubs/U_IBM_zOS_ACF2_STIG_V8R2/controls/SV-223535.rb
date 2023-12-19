control 'SV-223535' do
  title 'IBM z/OS JES2 input sources must be controlled in accordance with the proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ACF input screen enter:
SET CONTROL(GSO)
LIST LIKE(CLASMAP-) {to determine the resource type for JESINOUT}
NOTE: If CLASMAP defines JESINPUT as anything other than TYPE(INP), replace INP below with the appropriate three letters.

SET RESOURCE(INP)
LIST LIKE(-)

NOTE: If any of the following are not defined within the JES2 parameters, the resource in the JESINPUT resource class does not have to be defined.

Nodename is the NAME parameter in the NODE statement. Review the NJE node definitions by searching for NODE( in the JES2 parameters.

OFFn, where n is the number of the offload receiver. Review the spool offload receiver definitions by searching for OFF( in the JES2 parameters.

Rnnnn, where nnnn is the number of the remote workstation. Review the RJE node definitions by searching for RMT( in the JES2 parameters.

RDRnn, where nn is the number of the reader. Review the reader definitions by searching for RDR( in the JES2 parameters.

If the resources mentioned below are protected by generic and/or fully qualified rules defined to the JESINPUT resource class this is not a finding.

If a default access of PREVENT is specified for all resources this is not a finding.

If the ACF2 resources and/or generic equivalent identified below are defined with access restricted to the appropriate personnel this is not a finding.

NOTE: Use common sense during the analysis. For example, access to the offload input sources should be limited to systems personnel (e.g., operations staff).

NOTE: A default access of READ is allowed for input sources that are permitted to submit jobs for all users. No guidance on which input sources are appropriate for a default access of READ. However, common sense should prevail during the analysis. For example, a default access of READ would typically be inappropriate for RJE, NJE, offload, and STC input sources.

INTRDR (internal reader for batch jobs)
nodename (NJE node)
OFFn.- (spool offload receiver)
Rnnnn.- (RJE workstation)
RDRnn (local card reader)
STCINRDR (internal reader for started tasks)
TSUINRDR (internal reader for TSO logons)'
  desc 'fix', 'NOTE: If CLASMAP defines JESINPUT as anything other than TYPE(INP), replace INP below with the appropriate three letters.

Configure resources in the JESINPUT resource class (i.e., TYPE(INP)) granting read access to authorized users for each of the following input resources:
INTRDR (internal reader for batch jobs)
nodename (NJE node)
OFFn.- (spool offload receiver)
OFFn.JR (spool offload job receiver)
OFFn.SR (spool offload SYSOUT receiver)
Rnnnn.RDm (RJE workstation)
RDRnn (local card reader)
STCINRDR (internal reader for started tasks)
TSUINRDR (internal reader for TSO logons)

The resource definition will be generic if all of the resources of the same type have identical access controls (e.g., if all off load receivers are equivalent). The default access will be NONE except for sources that are permitted to submit jobs for all users. Those resources may be defined as either NONE or READ.

Nodename is the NAME parameter value specified on the NODE statement. Review the JES2 parameters for NJE node definitions by searching for NODE( in the JES2 parameters.

OFFn, where n is the number of the offload receiver. Determine the numbers by searching for OFF( in the JES2 parameters.

Rnnnn.RDm, where nnnn is the number of the remote workstation and m is the number of the reader. Determine the numbers by searching for .RD in the JES2 parameters.

RDRnn, where nn is the number of the reader. Determine the numbers by searching for RDR( in the JES2 parameters.

Ensure the following items are in effect:

The CLASMAP record defines the JESINPUT resource class.

Example:
SHOW CLASMAP

The resources mentioned in (b) are protected by generic and/or fully qualified rules defined to the JESINPUT resource class.

A default access of PREVENT is specified for all resources.

NOTE: A default access of READ is allowed for input sources that are permitted to submit jobs for all users. Currently, there is no guidance on which input sources are appropriate for a default access of READ. However, common sense should prevail during the analysis. For example, a default access of READ would typically be inappropriate for RJE, NJE, offload, and STC input sources.

Examples:
$KEY(STCINRDR) TYPE(INP)
- UID(*) PREVENT 

$KEY(TSUINRDR) TYPE(INP)
- UID(*) PREVENT 

$KEY(RDR*****) TYPE(INP)
$MEMBER(RDR#####) 
- UID(*) PREVENT 

$KEY(OFF*****) TYPE(INP) 
$MEMBER(OFF#####) 
JR UID(oper) SERVICE(READ)
JR UID(*) PREVENT 
SR UID(oper) SERVICE(READ)
SR UID(*) PREVENT 
- UID(oper) SERVICE(READ) 
- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25208r504660_chk'
  tag severity: 'medium'
  tag gid: 'V-223535'
  tag rid: 'SV-223535r533198_rule'
  tag stig_id: 'ACF2-JS-000080'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25196r504661_fix'
  tag 'documentable'
  tag legacy: ['SV-106879', 'V-97775']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
