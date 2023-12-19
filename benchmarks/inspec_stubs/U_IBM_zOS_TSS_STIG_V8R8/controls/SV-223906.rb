control 'SV-223906' do
  title 'CA-TSS must limit WRITE or greater access to all system-level product installation libraries to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Have the systems programmer for z/OS supply the following information:

The data set name and associated SREL for each SMP/E CSI utilized to maintain this system.

The data set name of all SMP/E TLIBs and DLIBs used for installation and production support. A comprehensive list of the SMP/E DDDEFs for all CSIs may be used if valid.

The ACP data set rules for system-level product installation libraries (e.g., SMP/E CSIs) allow inappropriate access.

The ACP data set rules for system-level product installation libraries (e.g., SMP/E CSIs) do not restrict WRITE or greater access to only z/OS systems programming personnel.

If all of the above are untrue, this is not a finding.

If any of the above is true, or if these data sets cannot be identified due to a lack of requested information, this is a finding.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect System-level product installation libraries.

Configure allocate access to all system-level product execution libraries to be limited to system programmers only.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25579r516117_chk'
  tag severity: 'medium'
  tag gid: 'V-223906'
  tag rid: 'SV-223906r856078_rule'
  tag stig_id: 'TSS0-ES-000330'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25567r516118_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107623', 'V-98519']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
