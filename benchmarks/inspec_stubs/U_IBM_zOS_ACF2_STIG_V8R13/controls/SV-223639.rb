control 'SV-223639' do
  title 'IBM z/OS startup user account for the z/OS UNIX Telnet Server must be defined properly.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
OMVS 
CD /etc
ls (to make sure OTELNET is active)
cat otelnetd.conf

If the otelnetd command specifies OMVS or OMVSKERN as the user, this is not a finding.

If the otelnetd command specifies any user other than OMVS or OMVSKERN, this is a finding.'
  desc 'fix', 'Configure the otelnetd startup command in the inetd.conf file to be defined for the z/OS UNIX kernel.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25312r501054_chk'
  tag severity: 'medium'
  tag gid: 'V-223639'
  tag rid: 'SV-223639r533198_rule'
  tag stig_id: 'ACF2-UT-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25300r501055_fix'
  tag 'documentable'
  tag legacy: ['SV-107087', 'V-97983']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
