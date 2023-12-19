control 'SV-223815' do
  title 'IBM z/OS DFSMS Program Resources must be properly defined and protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer to the load modules residing in the following Load libraries to determine program resource definitions:
 SYS1.DGTLLIB for DFSMSdfp/ISMF
 SYS1.DGTLLIB for DFSMSdss/ISMF
 SYS1.DFQLLIB for DFSMShsm

If the installation moves these modules to another load library the installation-defined load library must be used in the program protection.

If the RACF resources are defined with a default access of NONE, this is not a finding.

If the RACF resource access authorizations restrict access to the appropriate personnel, this is not a finding. 

(Refer to the chapter titled “Protecting the Storage Management Subsystem” in the IBM z/OS DFSMSdfp Storage Administration Guide to assist with guidance on appropriate access.)'
  desc 'fix', "(Note: The resource type, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product’s installation guide and can be site specific.)

Refer to the chapter titled “Protecting the Storage Management Subsystem” in the IBM z/OS DFSMSdfp Storage Administration Guide.

Use SMS Program Resources tables to determine the resources and access requirements for SMS Program Resources. Ensure the guidelines for the resource type, resources, and/or generic equivalent are specified.

The RACF resources as designated in the table above are defined with a default access of NONE.

The RACF resource access authorizations restrict access to the appropriate personnel as designated in the table above.

The following commands are provided as a sample for implementing resource controls:

RDEF PROGRAM ACBFUTO2 ADDMEM('SYS1.DSF.DGTLLIB'//NOPADCHK) - 
DATA('ADDED PER SRR PDI ZSMS0012 ') - 
AUDIT(FAILURE(READ)) UACC(NONE) OWNER(ADMIN)
PERMIT ACBFUTO2 CLASS(PROGRAM) ID(********)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25488r515133_chk'
  tag severity: 'medium'
  tag gid: 'V-223815'
  tag rid: 'SV-223815r604139_rule'
  tag stig_id: 'RACF-SM-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25476r515134_fix'
  tag 'documentable'
  tag legacy: ['V-98337', 'SV-107441']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
