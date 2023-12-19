control 'SV-224100' do
  title 'The IBM z/OS startup user account for the z/OS UNIX Telnet server must be properly defined.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
omvs
cd /etc
cat inetd.conf

If the "otelnetd" command specifies any user other than "OMVS" or "OMVSKERN", this is a finding.'
  desc 'fix', 'The user account used at the startup of "otelnetd" is specified in the "inetd" configuration file. This account is used to perform the identification and authentication of the user requesting the session. Because the account is only used until user authentication is completed, there is no need for a unique account for this function. The z/OS UNIX kernel account can be used.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25773r516699_chk'
  tag severity: 'medium'
  tag gid: 'V-224100'
  tag rid: 'SV-224100r877940_rule'
  tag stig_id: 'TSS0-UT-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25761r516700_fix'
  tag 'documentable'
  tag legacy: ['SV-108011', 'V-98907']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
