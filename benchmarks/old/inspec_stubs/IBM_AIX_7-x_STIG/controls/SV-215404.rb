control 'SV-215404' do
  title 'AIX must turn on enhanced Role-Based Access Control (RBAC) to isolate security functions from nonsecurity functions, to grant system privileges to other operating system admins, and prohibit user installation of system software without explicit privileged status.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For non-kernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

Operating system functionality will vary, and while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages, such as from an approved software repository.

AIX or software configuration management utility must enforce control of software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.

'
  desc 'check', 'Run the following command to retrieve the system RBAC mode:
# lsattr -E -l sys0 -a enhanced_RBAC
enhanced_RBAC true Enhanced RBAC Mode

If the RBAC mode is not "true", this is a finding.'
  desc 'fix', 'Enable the enhanced RBAC mode by running the following command:
# chdev -l sys0 -a enhanced_RBAC=true

Reboot the system:
# reboot'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16602r569500_chk'
  tag severity: 'medium'
  tag gid: 'V-215404'
  tag rid: 'SV-215404r853491_rule'
  tag stig_id: 'AIX7-00-003102'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-16600r569501_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000134-GPOS-00068', 'SRG-OS-000312-GPOS-00123', 'SRG-OS-000362-GPOS-00149']
  tag 'documentable'
  tag legacy: ['SV-101417', 'V-91319']
  tag cci: ['CCI-000213', 'CCI-001084', 'CCI-001812', 'CCI-002165']
  tag nist: ['AC-3', 'SC-3', 'CM-11 (2)', 'AC-3 (4)']
end
