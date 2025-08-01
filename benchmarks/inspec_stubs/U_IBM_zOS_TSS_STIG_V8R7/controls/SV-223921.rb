control 'SV-223921' do
  title 'IBM z/OS Operating system commands (MVS.) of the OPERCMDS resource class must be properly owned.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS OPERCMDS(MVS)

If the (MVS) resource is owned, this is not a finding.

If the (MVS) resource is not owned, this is a finding.

TSS LIST RDT RESCLASS(OPERCMDS)

If the (MVS) resource is not OWNED and the OPERCMDS class does not have DEFPROT as an attribute, this is a finding.'
  desc 'fix', 'z/OS system command controls are provided via resources in the OPERCMDS resource class. Configure (MVS) of the OPERCMDS resource class to be properly owned or at a minimum the OPERCMDS resource in the RDT specifies the DEFPROT attribute. Name the actual owning ACID specified for deptacid in accordance with installation recommendations. 

When protecting the facilities for z/OS system commands via the OPERCMDS class, use the following controls:

(1) Prevent access to the z/OS resources by default, and log all access. Create generic and specific permissions with logging as required using the required controls for z/OS System Commands listed in ACP00282. 

For example:

TSS ADDTO(deptacid) OPERCMDS(MVS.)
TSS PERMIT(usracid) OPERCMDS(MVS.ACTIVATE) ACTION(AUDIT)
TSS PERMIT(usracid) OPERCMDS(MVS.CANCEL.JOB.) ACTION(AUDIT)
TSS PERMIT(usracid) OPERCMDS(MVS.CONTROL.) ACCESS(UPDATE)
ACTION(AUDIT)
TSS PERMIT(usracid) OPERCMDS(MVS.DISPLAY.) ACCESS(READ)
TSS PERMIT(usracid) OPERCMDS(MVS.MONITOR) ACCESS(READ)
TSS PERMIT(usracid) OPERCMDS(MVS.STOPMN) ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25594r516162_chk'
  tag severity: 'medium'
  tag gid: 'V-223921'
  tag rid: 'SV-223921r561402_rule'
  tag stig_id: 'TSS0-ES-000480'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25582r516163_fix'
  tag 'documentable'
  tag legacy: ['V-98549', 'SV-107653']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
