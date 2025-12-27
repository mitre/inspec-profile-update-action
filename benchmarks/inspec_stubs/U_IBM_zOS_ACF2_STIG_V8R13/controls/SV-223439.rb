control 'SV-223439' do
  title 'IBM z/OS must protect dynamic lists in accordance with proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'From a command input screen enter:
SET RESOURCE (FAC) 
SET VERBOSE
LIST LIKE (CSV-)

NOTE: If CLASMAP defines FACILITY as anything other than the default of TYPE(FAC), replace FAC with the appropriate three letters.

If the ACF2 resources and/or generic equivalent are defined with a default access of PREVENT, this is not a finding.

If the ACF2 resources and/or generic equivalent identified below will be defined with LOG and SERVICE(UPDATE) access restricted to system programming personnel, this is not a finding.

CSVAPF.
CSVAPF.MVS.SETPROG.FORMAT.DYNAMIC
CSVAPF.MVS.SETPROG.FORMAT.STATIC
CSVDYLPA.
CSVDYNEX.
CSVDYNEX.LIST
CSVDYNL.
CSVDYNL.UPDATE.LNKLST
CSVLLA.

If the ACF2 CSVDYNEX.LIST resource and/or generic equivalent will be defined with LOG and SERVICE(UPDATE) access restricted to system programming personnel, this is not a finding.

If the ACF2 CSVDYNEX.LIST resource and/or generic equivalent will be defined with SERVICE(READ) access restricted to auditors, this is not a finding.

If the products CICS and/or CONTROL-O are on the system, the ACF2 access to the CSVLLA resource and/or generic equivalent will be defined with LOG and SERVICE(UPDATE) access restricted to the CICS and CONTROL-O STC logonids, this is not a finding.

If any software product requires access to dynamic LPA updates on the system, the ACF2 access to the CSVDYLPA resource and/or generic equivalent will be defined with LOG and SERVICE(UPDATE) only after the product has been validated with the appropriate STIG or SRG for compliance AND receives documented and filed authorization that details the need and any accepted risks from the site ISSM or equivalent security authority, this is not a finding.

Note: In the above, SERVICE(UPDATE) can be substituted with ADD, CONTROL, or LOG/ALLOW. Review the rules definitions in the ACF2 documentation when specifying SERVICE(UPDATE).'
  desc 'fix', "Configure the Dynamic List resources to be defined to the IBMFAC resource class and protected. Only system programmers and a limited number of authorized users and Approved authorized Started Tasks are able to issue these commands. All access is logged.

Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The resource class, actual resources, and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.

The required CSV-prefixed Facility Class resources are listed below. These resources and/or generic equivalents should be defined and permitted as required with only z/OS systems programmers and logging enabled. Minimum required list of CSV-prefixed resources:

CSVAPF.-
CSVAPF.MVS.SETPROG.FORMAT.DYNAMIC
CSVAPF.MVS.SETPROG.FORMAT.STATIC
CSVDYLPA.-
CSVDYLPA.ADD.-
CSVDYLPA.DELETE.-
CSVDYNEX.-
CSVDYNEX.LIST
CSVDYNL.-
CSVDYNL.UPDATE.LNKLST
CSVLLA.-

Limit authority to those resources to z/OS systems programmers. Restrict to the absolute minimum number of personnel with LOG and SERVICE(UPDATE) access.

Sample commands are shown here to accomplish one set of resources:

$KEY(CSVAPF) TYPE(FAC) 
MVS.SETPROG.- UID(sysprgmr) LOG
MVS.SETPROG.FORMAT.DYNAMIC.- UID(sysprgmr) LOG 
MVS.SETPROG.FORMAT.STATIC.- UID(sysprgmr) LOG
MVS.SETPROG.FORMAT.- UID(sysprgmr) LOG 
MVS.SETPROG.FORMAT.- UID(*) PREVENT
- UID(sysprgmr) LOG 
- UID(*) PREVENT

SET R(FAC)
COMPILE 'ACF2.xxxx.FAC(CSVAPF)' STORE

F ACF2,REBUILD(FAC)

The CSVDYLPA.ADD resource can be permitted to BMC Mainview, CA 1, and CA Common Services STC logonids with LOG and SERVICE(UPDATE) access.

The CSVDYLPA.DELETE resource can be permitted to CA 1 and CA Common Services STC logonids with LOG and SERVICE(UPDATE) access.

Sample commands are shown here to accomplish one set of resources:

$KEY(CSVDYLPA) TYPE(FAC) 
ADD.- UID(sysprgmr) LOG SERVICE(UPDATE)
ADD.- UID(BMC Mainview STC) LOG SERVICE(UPDATE)
ADD.- UID(CA 1 STC) LOG SERVICE(UPDATE)
ADD.- UID(CCS STC) LOG SERVICE(UPDATE)
DELETE.- UID(sysprgmr) LOG SERVICE(UPDATE)
DELETE.- UID(CA 1 STC) LOG SERVICE(UPDATE)
DELETE.- UID(CCS STC) LOG SERVICE(UPDATE)
- UID(sysprgmr) LOG
- UID(*) PREVENT

SET R(FAC)
COMPILE 'ACF2.xxxx.FAC(CSVDYLPA)' STORE

F ACF2,REBUILD(FAC)

The CSVDYNEX.LIST resource and/or generic equivalent will be defined with LOG and SERVICE(UPDATE) access restricted to system programming personnel.

The CSVDYNEX.LIST resource and/or generic equivalent will be defined with SERVICE(READ) access with ALLOW restricted to auditors.

Sample commands are shown here to accomplish this:

$KEY(CSVDYNEX) TYPE(FAC) 
LIST.- UID(sysprgmr) LOG
LIST.- UID(auditor) SERVICE(READ) ALLOW
- UID(sysprgmr) LOG 
- UID(*) PREVENT

SET R(FAC)
COMPILE 'ACF2.xxxx.FAC(CSVDYNEX)' STORE

F ACF2,REBUILD(FAC)

The CSVLLA resource can be permitted to CICS and CONTROL-O STC logonids with LOG and SERVICE(UPDATE) access.

Sample commands are shown here to accomplish one set of resources:

$KEY(CSVLLA) TYPE(FAC) 
- UID(sysprgmr) LOG
- UID(CICS STC logonids) LOG SERVICE(UPDATE)
- UID(CONTROL-O STC logonid) LOG SERVICE(UPDATE)
- UID(*) PREVENT

SET R(FAC)
COMPILE 'ACF2.xxxx.FAC(CSVLLA)' STORE

F ACF2,REBUILD(FAC)"
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25112r858847_chk'
  tag severity: 'high'
  tag gid: 'V-223439'
  tag rid: 'SV-223439r861164_rule'
  tag stig_id: 'ACF2-ES-000180'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25100r858848_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-106679', 'V-97575']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
