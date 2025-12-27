control 'SV-223749' do
  title 'IBM z/OS JES2 output devices must be properly controlled for classified systems.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
RL WRITER *

If the RACF resources and/or generic equivalent identified below are defined with access restricted to the appropriate personnel, this is not a finding.

JES2.LOCAL.devicename
JES2.LOCAL.OFFn.*
JES2.LOCAL.OFFn.JT
JES2.LOCAL.OFFn.ST
JES2.LOCAL.PRTn
JES2.LOCAL.PUNn
JES2.NJE.nodename
JES2.RJE.devicename

Note: Examples of appropriate might be access to the offload input sources is limited to systems personnel (e.g., operations staff) as directed by site operations and the site security plan.'
  desc 'fix', 'Configure access authorization for resources defined to the WRITER resource class to be restricted to the operators and system programmers on a classified system only.

Define resources in the ACP’s respective WRITER class for each of the following output destinations:

JES2.LOCAL.devicename
JES2.LOCAL.OFFn.*
JES2.LOCAL.OFFn.JT
JES2.LOCAL.OFFn.ST
JES2.LOCAL.PRTn
JES2.LOCAL.PUNn
JES2.NJE.nodename
JES2.RJE.devicename'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25422r514935_chk'
  tag severity: 'medium'
  tag gid: 'V-223749'
  tag rid: 'SV-223749r604139_rule'
  tag stig_id: 'RACF-JS-000050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25410r514936_fix'
  tag 'documentable'
  tag legacy: ['V-98205', 'SV-107309']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
