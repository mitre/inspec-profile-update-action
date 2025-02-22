control 'SV-224078' do
  title 'IBM z/OS UNIX SUPERUSER resources must be protected in accordance with guidelines.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS UNIXPRIV(*)

If the TSS resources and/or generic equivalent for SUPERUSER. is not owned enter:
TSS LIST RDT

If the TSS resources and/or generic equivalent for SUPERUSER. is not owned or DEFPROT is specified for the resource class, this is a finding.

From the ISPF Command Shell enter:
TSS WHOHAS SURROGAT(SUPERUSER.)

If the TSS resource access authorizations restrict BPX.SRV.user to system software processes (e.g., web servers) that act as servers under z/OS UNIX, this is not a finding.'
  desc 'fix', 'Ensure that all SUPERUSER resources for the UNIXPRIV resource class are restricted to appropriate system tasks and/or system programming personnel.

Review the following items for the UNIXPRIV resource class:

-The TSS owner defined for the SUPERUSER resource.
-There are no TSS rules that allow access to the SUPERUSER resource.
-There is no TSS rule for CHOWN.UNRESTRICTED defined.
-The TSS rules for each of the SUPERUSER resources listed in the z/OS UNIX System Services Planning, Establishing UNIX security, restrict access to appropriate system tasks or systems programming personnel.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25751r516633_chk'
  tag severity: 'high'
  tag gid: 'V-224078'
  tag rid: 'SV-224078r561402_rule'
  tag stig_id: 'TSS0-US-000050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25739r516634_fix'
  tag 'documentable'
  tag legacy: ['V-98863', 'SV-107967']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
