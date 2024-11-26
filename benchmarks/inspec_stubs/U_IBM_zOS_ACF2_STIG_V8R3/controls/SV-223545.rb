control 'SV-223545' do
  title 'IBM z/OS special privileges must be assigned on an as-needed basis to LOGONIDs associated with STCs and LOGONIDs that need to execute TSO in batch.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET LID 
SET VERBOSE
LIST IF(ACCTPRIV OR CONSOLE OR OPERATOR OR MOUNT)

If the ACCTPRIV privilege is restricted to security personnel, this is not a finding.

If the CONSOLE and OPERATOR privileges are restricted to authorized systems personnel (e.g., systems programming personnel, operations staff, etc), this is not a finding.

If the MOUNT privilege is restricted to DASD batch users only, this is not a finding.'
  desc 'fix', 'Review all Logonids for the following and ensure that only authorized users with justification are given access to the privileges.

The ACCTPRIV privilege is restricted for used to the domain level security personnel (ISSO/ISSM).

The CONSOLE and OPERATOR privileges are restricted to authorized systems personnel (e.g., systems programming personnel, operations staff, etc).

The MOUNT privilege is restricted to DASD batch users only on an as-needed basis to execute TSO in batch.

Ensure that all privileges are kept to a minimum and are controlled and documented.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25218r504678_chk'
  tag severity: 'medium'
  tag gid: 'V-223545'
  tag rid: 'SV-223545r533198_rule'
  tag stig_id: 'ACF2-OS-000090'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25206r504679_fix'
  tag 'documentable'
  tag legacy: ['SV-106899', 'V-97795']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
