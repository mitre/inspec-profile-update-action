control 'SV-223986' do
  title 'IBM z/OS RJE workstations and NJE nodes must be controlled in accordance with STIG requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer to SYS1.PARMLIB (JES2PARM)
For each node entry 

If all JES2 defined NJE nodes and RJE workstations have a profile defined in the IBMFAC resource class, this is not a finding.

Notes: Nodename is the NAME parameter value specified on the NODE statement. Review the JES2 parameters for NJE node definitions by searching for "NODE(" in the report.
Workstation is RMTnnnn, where nnnn is the number on the RMT statement. Review the JES2 parameters for RJE workstation definitions by searching for "RMT(" in the report.
NJE. and RJE. definitions will force logonid and password protection of all NJE and RJE connections respectively. This method is acceptable in lieu of using discrete profiles.

If any JES2 defined NJE node or RJE workstation is not owned in the IBMFAC class, this is a finding.'
  desc 'fix', 'Ensure associated USERIDs exist for all RJE/NJE sources and review the authorizations for these remote facilities. Develop a plan of action and implement the changes as required by the OS/390 STIG.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25659r516357_chk'
  tag severity: 'medium'
  tag gid: 'V-223986'
  tag rid: 'SV-223986r561402_rule'
  tag stig_id: 'TSS0-JS-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25647r516358_fix'
  tag 'documentable'
  tag legacy: ['V-98679', 'SV-107783']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
