control 'SV-207383' do
  title 'The VMM must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. VMMs use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the VMM.'
  desc 'check', 'Verify the VMM enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7640r365559_chk'
  tag severity: 'medium'
  tag gid: 'V-207383'
  tag rid: 'SV-207383r378772_rule'
  tag stig_id: 'SRG-OS-000080-VMM-000470'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-7640r365560_fix'
  tag 'documentable'
  tag legacy: ['V-56957', 'SV-71217']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
