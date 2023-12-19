control 'SV-224077' do
  title 'IBM z/OS UNIX resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS SURROGAT(*)

If the TSS resources and/or generic equivalent for BPX. is not owned enter:
TSS LIST RDT

If the TSS resources and/or generic equivalent for BPX. is not owned or DEFPROT is specified for the resource class, this is a finding.

From the ISPF Command Shell enter:
TSS WHOHAS SURROGAT(BPX.)

If the TSS resource access authorizations restrict BPX.SRV.user to system software processes (e.g., web servers) that act as servers under z/OS UNIX, this is not a finding. 

If the RACF rules for all BPX.SRV.user SURROGAT resources restrict access to authorized users identified in the Site Security Plan, this is not a finding.'
  desc 'fix', 'Ensure that BPX. SRV.userid resources are properly protected and access is restricted to appropriate system tasks or systems programming personnel.

SURROGAT class BPX resources are used in conjunction with server applications that are performing tasks on behalf of client users that may not supply an authenticator to the server. This can be the case when clients are otherwise validated or when the requested service is performed from userids representing groups.

Ensure there is a TSS owner defined for the (BPX.) SURROGAT class resource.
For Example:
TSS ADD(dept) SURROGAT(BPX.)

Ensure the TSS rules for all BPX.SRV.user SURROGAT resources restrict access to system software processes (e.g., web servers) that act as servers under z/OS UNIX and to users whose access and approval are identified in the Site Security Plan.

For Example:
TSS PERMIT(<websrv>) SURROGAT(BPX.SRV.<webadm>)
ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25750r856139_chk'
  tag severity: 'medium'
  tag gid: 'V-224077'
  tag rid: 'SV-224077r877915_rule'
  tag stig_id: 'TSS0-US-000040'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25738r856140_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000326-GPOS-00126']
  tag 'documentable'
  tag legacy: ['V-98861', 'SV-107965']
  tag cci: ['CCI-000213', 'CCI-002233']
  tag nist: ['AC-3', 'AC-6 (8)']
end
