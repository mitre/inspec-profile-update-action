control 'SV-223989' do
  title 'IBM z/OS JES2 output devices must be controlled in accordance with the proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer the JES2PARM member of SYS1.PARMLIB
Review the WRITER resource in the JESINPUT resource class:

NOTE: If the WRITER resource is not defined within the JES2 parameters, the resource in the JESINPUT resource class does not have to be owned.

From the ISPF Command Shell enter:
TSS WHOOWNS JESINPUT(WRITER)

If the WRITER resource is owned by generic and/or fully qualified entries in the JESINPUT resource class, this is not a finding.'
  desc 'fix', 'Ensure the following items are in effect:

-The JES2. resource is owned in the WRITER resource class.

For Example:
The following command may be used to establish default protection for resources defined to the WRITER resource class:
TSS ADDTO(deptacid) WRITER(JES2.)

-The ownership of all WRITER resources is appropriate.

Grant read access to authorized users for each of the following WRITER resource class output destinations:

JES2.LOCAL.devicename
JES2.LOCAL.OFF*.JT
JES2.LOCAL.OFF*.ST
JES2.LOCAL.PRT*
JES2.LOCAL.PUN*
JES2.NJE.nodename
JES2.RJE.devicename

The following is an example of granting operators with a profile ACID of jesopracid permission to off load SYSOUT data sets into any SPOOL off load processor after obtaining permission from the ISSO:

TSS PERMIT(jesopracid) WRITER(JES2.LOCAL.OFF*.ST) -
ACCESS(READ) ACTION(AUDIT)

The resource definition should be generic if all of the resources of the same type have identical access controls (e.g., if all off load transmitters are equivalent).'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25662r516366_chk'
  tag severity: 'medium'
  tag gid: 'V-223989'
  tag rid: 'SV-223989r561402_rule'
  tag stig_id: 'TSS0-JS-000050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25650r516367_fix'
  tag 'documentable'
  tag legacy: ['SV-107789', 'V-98685']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
