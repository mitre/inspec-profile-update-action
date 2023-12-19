control 'SV-223907' do
  title 'CA-TSS must limit WRITE or greater access to the JES2 System data sets (e.g., Spool, Checkpoint, and Initialization parameters) to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'The ESM data set rules for the JES2 System data sets (e.g., Spool, Checkpoint, and Initialization parameters) do not restrict WRITE or greater access to only z/OS systems programming personnel.

The ESM data set rules for the JES2 System data sets (e.g., Spool, Checkpoint, and Initialization parameters) allow inappropriate access not documented and approved by ISSO.

If both of the above are untrue, this is not a finding.

If either of the above is true, this is a finding.'
  desc 'fix', 'Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect JES2 System data sets (spool, checkpoint, and parmlib data sets).

Configure WRITE or greater access to JES2 System data sets (spool, checkpoint, and parmlib data sets) to be limited to system programmers only. 
Access other than this should be documented and approved by the ISSO. (Example: All SYS1.HASP* data sets.)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25580r516120_chk'
  tag severity: 'medium'
  tag gid: 'V-223907'
  tag rid: 'SV-223907r561402_rule'
  tag stig_id: 'TSS0-ES-000340'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25568r516121_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98521', 'SV-107625']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
