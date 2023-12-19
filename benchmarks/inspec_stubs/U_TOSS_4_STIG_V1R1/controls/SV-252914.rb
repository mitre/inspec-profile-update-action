control 'SV-252914' do
  title 'TOSS must require authentication upon booting into emergency or rescue modes.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Check to see if the system requires authentication for rescue or emergency mode with the following command:

$ sudo grep sulogin-shell /usr/lib/systemd/system/rescue.service

ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue

If the "ExecStart" line is configured for anything other than "/usr/lib/systemd/systemd-sulogin-shell rescue", commented out, or missing, this is a finding.'
  desc 'fix', 'Configure the system to require authentication upon booting into emergency or rescue mode by adding the following line to the "/usr/lib/systemd/system/rescue.service" file.

ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56367r824064_chk'
  tag severity: 'medium'
  tag gid: 'V-252914'
  tag rid: 'SV-252914r824066_rule'
  tag stig_id: 'TOSS-04-010030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-56317r824065_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
