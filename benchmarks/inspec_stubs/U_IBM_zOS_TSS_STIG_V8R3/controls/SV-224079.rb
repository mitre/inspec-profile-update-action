control 'SV-224079' do
  title 'IBM z/OS UNIX MVS data sets or HFS objects must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Refer to the proper BPXPRMxx member in SYS1.PARMLIB 

If the ESM data set rules for the data sets referenced in the ROOT and the MOUNT statements in BPXPRMxx restrict update access to the z/OS UNIX kernel (i.e., OMVS or OMVSKERN), this is not a finding.

If the ESM data set rules for the data set referenced in the ROOT and the MOUNT statements in BPXPRMxx restrict WRITE or greater access to systems programming personnel, this is not a finding.'
  desc 'fix', 'Review the access authorizations defined in the ACP for the MVS data sets that contain operating system components and for the MVS data sets that contain HFS file systems and ensure that they conform to the specifications below.

 Review the UNIX permission bits on the HFS directories and files and ensure that they conform to the specifications below:

Define ESM data set rules for the data sets referenced in the ROOT and the MOUNT statements in BPXPRMxx to restrict update access to the z/OS UNIX kernel (i.e., OMVS or OMVSKERN).

Define ESM data set rules for the data sets referenced in the ROOT and the MOUNT statements in BPXPRMxx to restrict WRITE or greater access to systems programming personnel.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25752r516636_chk'
  tag severity: 'medium'
  tag gid: 'V-224079'
  tag rid: 'SV-224079r561402_rule'
  tag stig_id: 'TSS0-US-000060'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25740r516637_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['SV-107969', 'V-98865']
  tag cci: ['CCI-000213', 'CCI-001499']
  tag nist: ['AC-3', 'CM-5 (6)']
end
