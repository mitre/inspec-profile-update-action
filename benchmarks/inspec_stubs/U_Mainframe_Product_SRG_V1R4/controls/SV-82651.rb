control 'SV-82651' do
  title 'The Mainframe Product must enforce approved authorizations for security administrator access to sensitive information and system resources in accordance with applicable access control policies.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions.'
  desc 'check', 'If an external security manager is used, check the external security manager rules and configuration.

If there are no rules for these resources or the rules do not restrict security administrator access in accordance with applicable access control policies, this is a finding.

Examine installation and configuration settings.

Verify that the Mainframe Product enforces security administrator access to information and system resources in accordance with applicable access control policies. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to enforce role and/or resource access in accordance with applicable access control policies. This can be accomplished using an external security manager.

Configure the external security manager to restrict security administrator access according to applicable access control policies.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68721r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68161'
  tag rid: 'SV-82651r1_rule'
  tag stig_id: 'SRG-APP-000033-MFP-000057'
  tag gtitle: 'SRG-APP-000033-MFP-000057'
  tag fix_id: 'F-74277r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
