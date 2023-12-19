control 'SV-223990' do
  title 'IBM z/OS JES2 output devices must be properly controlled for classified systems.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'If the Classification of the system is unclassified, this is not applicable.

From the ISPF Command Shell enter:
TSS WHOHAS WRITER(JES2.)

If the TSS WRITER resource or generic equivalent identified above is defined with access restricted to the appropriate personnel, this is not a finding.

If the TSS WRITER resource or generic equivalent identified above is not defined with access restricted to the appropriate personnel, this is a finding.

From the ISPF Command Shell enter:
TSS LIST RDT(*)

If the JESINPUT RESOURCE does not have DEFPROT as an attribute, this is a finding.'
  desc 'fix', "Configure access authorization for resources defined to the WRITER resource class to be restricted to the operators and system programmers on a classified system only.

Define resources in the ACP's respective WRITER class for each of the following output destinations:

JES2.LOCAL.devicename
JES2.LOCAL.OFFn.*
JES2.LOCAL.OFFn.JT
JES2.LOCAL.OFFn.ST
JES2.LOCAL.PRTn
JES2.LOCAL.PUNn
JES2.NJE.nodename
JES2.RJE.devicename

The resource definition will be generic if all of the resources of the same type have identical access controls (e.g., if all off load transmitters are equivalent). If all users are permitted to route output to a specific destination, the resource controlling it may be defined with a default access of either NONE or READ. Otherwise it will be defined with a default access of NONE."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25663r516369_chk'
  tag severity: 'medium'
  tag gid: 'V-223990'
  tag rid: 'SV-223990r868976_rule'
  tag stig_id: 'TSS0-JS-000060'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25651r868975_fix'
  tag 'documentable'
  tag legacy: ['V-98687', 'SV-107791']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
