control 'SV-104485' do
  title 'Symantec ProxySG must be configured to enforce user authorization to implement least privilege.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Network devices use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the network device to control access between administrators (or processes acting on behalf of administrators) and objects (e.g., device commands, files, records, processes) in the network device.'
  desc 'check', 'Obtain a list of authorized personnel or host IP addresses and associated roles/privileges. Verify there are no unauthorized users/host IP addresses. Verify there are no users or host IP addresses with excess privileges.

1. Log on to the Web Management Console.
2. Click Configuration >> Policy >> Visual Policy Manager.
3. Click the "Launch" button. 
4. Click the "Admin Access" layer. 

Verify that any users, hosts, and groups listed in the "source" field of each rule that have an action of "Allow" are authorized administrators with read-write, read-only, or deny.

If users or hosts are configured for excess privileges, this is a finding.'
  desc 'fix', 'Obtain a list of authorized personnel or host IP addresses and associated roles/privileges. Remove any unauthorized users or excess privileges.

1. Log on to the Web Management Console.
2. Click Configuration >> Policy >> Visual Policy Manager.
3. Click the "Launch" button. 
4. Click the "Admin Access" layer. 
5. Delete unauthorized users or host IP addresses and adjust or correct user authorizations for "allow read-only" or "allow read-write".'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93845r1_chk'
  tag severity: 'high'
  tag gid: 'V-94655'
  tag rid: 'SV-104485r1_rule'
  tag stig_id: 'SYMP-NM-000020'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-100773r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
