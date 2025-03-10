control 'SV-223533' do
  title 'IBM z/OS JES2 output devices must be properly controlled for Classified Systems.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'If the Classification of the system is Unclassified, this is not applicable.

Verify that the accesses for WRITER resources are restricted.

If the following guidance is true, this is not a finding.

The ACF2 resources and/or generic equivalent are defined with a default access of PREVENT.

The ACF2 resources and/or generic equivalent identified below will be defined with access restricted to the operators and system programming personnel:

JES2.LOCAL.devicename
JES2.LOCAL.OFFn.*
JES2.LOCAL.OFFn.JT
JES2.LOCAL.OFFn.ST
JES2.LOCAL.PRTn
JES2.LOCAL.PUNn
JES2.NJE.nodename
JES2.RJE.devicename

NOTE: Common sense should prevail during the analysis. For example, access to the offload output destinations should be limited to only systems personnel (e.g., operations staff/system programmers) on a classified system.'
  desc 'fix', 'Configure the access authorization for resources defined to the WRITER resource class to be restricted to the operators and system programmers on a classified system only.

Define resources in the ACP’s respective WRITER class for each of the following output destinations:

JES2.LOCAL.devicename
JES2.LOCAL.OFFn.*
JES2.LOCAL.OFFn.JT
JES2.LOCAL.OFFn.ST
JES2.LOCAL.PRTn
JES2.LOCAL.PUNn
JES2.NJE.nodename
JES2.RJE.devicename

The resource definition will be generic if all of the resources of the same type have identical access controls (e.g., if all off load transmitters are equivalent). If all users are permitted to route output to a specific destination, the resource controlling it may be defined with a default access of either NONE or READ. Otherwise it will be defined with a default access of NONE.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25206r504654_chk'
  tag severity: 'medium'
  tag gid: 'V-223533'
  tag rid: 'SV-223533r533198_rule'
  tag stig_id: 'ACF2-JS-000060'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25194r504655_fix'
  tag 'documentable'
  tag legacy: ['SV-106875', 'V-97771']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
