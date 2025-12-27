control 'SV-223844' do
  title 'IBM z/OS UNIX resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'From the ISPF Command Shell enter:
RL SURROGAT BPX.SRV AUTHUSER 

If the RACF rules for all BPX.SRV.user SURROGAT resources specify a default access of NONE, this is not a finding.

If the RACF rules for all BPX.SRV.user SURROGAT resources restrict access to system software processes (e.g., web servers) that act as servers under z/OS UNIX, this is not a finding.

If the RACF rules for all BPX.SRV.user SURROGAT resources restrict access to authorized users identified in the Site Security Plan, this is not a finding.'
  desc 'fix', 'SURROGAT class BPX resources are used in conjunction with server applications that are performing tasks on behalf of client users that may not supply an authenticator to the server. This can be the case when clients are otherwise validated or when the requested service is performed from userids representing groups.

Configure the default access for each BPX.SRV.userid resource must be no access. Access can be permitted only to system software processes that act as servers under z/OS UNIX (e.g., web servers) and users whose access and approval are identified in the Site Security Plan.

A sample is provided here:

RDEF SURROGAT BPX.SRV.user UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ))

-RACF rules for all BPX.SRV.user SURROGAT resources must restrict access to system software processes (e.g., web servers) that act as servers under z/OS UNIX.

RDEF SURROGAT BPX.SRV.user UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ))
PE BPX.SRV.user CL(SURROGAT) ID(<server>)'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25517r572059_chk'
  tag severity: 'medium'
  tag gid: 'V-223844'
  tag rid: 'SV-223844r604139_rule'
  tag stig_id: 'RACF-US-000070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25505r572060_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000326-GPOS-00126']
  tag 'documentable'
  tag legacy: ['SV-107499', 'V-98395']
  tag cci: ['CCI-000213', 'CCI-002233']
  tag nist: ['AC-3', 'AC-6 (8)']
end
