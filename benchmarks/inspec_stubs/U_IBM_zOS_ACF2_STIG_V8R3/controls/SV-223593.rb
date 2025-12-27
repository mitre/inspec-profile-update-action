control 'SV-223593' do
  title 'IBM z/OS DFSMS resource class(es) must be defined to the GSO CLASMAP record in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET CONTROL(GSO)
SHOW CLASMAP

If both MGMTCLAS and STORCLAS resource classes are defined, this is not a finding.'
  desc 'fix', 'Define the GSO CLASMAP record with the following definitions:

MGMTCLAS
STORCLAS

Ensure both resource classes above are defined.

Example:
SHOW SAFDEF

SET CONTROL(GSO)
INSERT CLASMAP.MGMTCLAS MGM(8)

F ACF2,REFRESH(ALL)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25266r500914_chk'
  tag severity: 'medium'
  tag gid: 'V-223593'
  tag rid: 'SV-223593r533198_rule'
  tag stig_id: 'ACF2-SM-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25254r500915_fix'
  tag 'documentable'
  tag legacy: ['V-97891', 'SV-106995']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
