control 'SV-223436' do
  title 'ACF2 Classes required to properly security the z/OS UNIX environment must be ACTIVE.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET CONTROL(GSO)
SHOW CLASMAP

If the CLASMAP DEFINITIONS list does not include entries for the FACILITY, SURROGAT, and UNIXPRIV resource classes, this is a finding.

NOTE: TYPE CODES values should be unique for each resource. The default TYPE CODE values should be FAC, SUR, and UNI.'
  desc 'fix', 'Define the CLASMAP DEFINITIONS to include entries for the FACILITY, SURROGAT, and UNIXPRIV resource classes.

NOTE: TYPE CODES values should be unique for each resource. The default TYPE CODE values should be FAC, SUR, and UNI.

Example:
TSO ACF
SHOW CLASMAP

ACF
SET CONTROL(GSO)
INSERT CLASMAP.FACILITY  RESOURCE(FACILITY) RSRCTYPE(FAC)  ENTITYTLN (39)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25109r836671_chk'
  tag severity: 'medium'
  tag gid: 'V-223436'
  tag rid: 'SV-223436r836693_rule'
  tag stig_id: 'ACF2-ES-000150'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25097r836672_fix'
  tag 'documentable'
  tag legacy: ['V-97569', 'SV-106673']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
