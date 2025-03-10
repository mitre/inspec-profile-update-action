control 'SV-223918' do
  title 'IBM z/OS system commands must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From a command screen enter:
TSS WHOHAS OPERCMDS(MVS)

If any of below is untrue for any z/OS system command resource, this is a finding.

Access to MVS resource of the OPERCMDS class is restricted to a limited number of authorized users, and all access logged.
Access to "MVS.**" is not allowed.

Access to z/OS system commands as defined in the table entitled MVS commands, RACF access authorities, and resource names, in the IBM z/OS MVS System Commands manual, is restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users).

NOTE: Use the GROUP category specified in the table referenced above as a guideline to determine appropriate personnel access to system commands.

NOTE: The (MVS.SEND) Command will not be a finding if used by all.

Access to specific z/OS system commands is logged as indicated in the table entitled MVS commands, RACF access authorities, and resource names, in the IBM z/OS MVS System Commands manual.'
  desc 'fix', 'Ensure access to the MVS resource of the OPERCMDS class is restricted to a limited number of authorized users, and all access is logged. Ensure access to z/OS system commands as defined in the table entitled MVS commands, RACF access authorities, and resource names, in the IBM z/OS MVS System Commands manual is restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users). 

Ensure no access is granted at level MVS.**.
NOTE: Use the GROUP category specified in the table referenced above as a guideline to determine appropriate personnel access to system commands. 
NOTE: The (MVS.SEND) Command will not be a finding if used by all. 

Example:
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
  tag check_id: 'C-25591r516153_chk'
  tag severity: 'medium'
  tag gid: 'V-223918'
  tag rid: 'SV-223918r877759_rule'
  tag stig_id: 'TSS0-ES-000450'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25579r516154_fix'
  tag 'documentable'
  tag legacy: ['V-98543', 'SV-107647']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
