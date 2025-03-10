control 'SV-237917' do
  title 'CA VM:Secure product NORULE record in the SECURITY CONFIG file must be configured to REJECT.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Examine the “SECURITY CONFIG” file.

If a “NORULE” record exists and is set to “REJECT”, this is not a finding.'
  desc 'fix', 'Configure the “SECURITY CONFIG” file to include a “NORULE” record that is set to “REJECT”.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41127r649589_chk'
  tag severity: 'medium'
  tag gid: 'V-237917'
  tag rid: 'SV-237917r649591_rule'
  tag stig_id: 'IBMZ-VM-000600'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-41086r649590_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000480-GPOS-00228', 'SRG-OS-000480-GPOS-00229', 'SRG-OS-000104-GPOS-00051', 'SRG-OS-000121-GPOS-00062', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['SV-93587', 'V-78881']
  tag cci: ['CCI-000213', 'CCI-000366', 'CCI-000764', 'CCI-000804', 'CCI-001774']
  tag nist: ['AC-3', 'CM-6 b', 'IA-2', 'IA-8', 'CM-7 (5) (b)']
end
