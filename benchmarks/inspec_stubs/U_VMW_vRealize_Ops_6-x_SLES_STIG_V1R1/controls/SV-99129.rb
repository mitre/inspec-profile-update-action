control 'SV-99129' do
  title 'The SLES for vRealize must require root password authentication upon booting into single-user mode.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Verify that root password is required for single user mode logon with the following command:

# grep sulogin /etc/inittab

Expected result:
~~:S:respawn:/sbin/sulogin

If the expected result is not displayed, this is a finding.'
  desc 'fix', "Configure SLES for vRealize to require root password login with single user mode use the following command:

# echo '~~:S:respawn:/sbin/sulogin' >> /etc/inittab"
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88171r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88479'
  tag rid: 'SV-99129r1_rule'
  tag stig_id: 'VROM-SL-000415'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-95221r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
