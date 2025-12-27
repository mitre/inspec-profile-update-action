control 'SV-223437' do
  title 'Access to IBM z/OS special privilege TAPE-LBL or TAPE-BLP must be limited and/or justified.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET LID
SET VERBOSE
LIST IF(TAPE-LBL OR TAPE-BLP)

If the number of users granted the special privileges TAPE-LBL or TAPE-BLP is strictly controlled and limited to systems programmer and operations personnel, this is not a finding.

If the number of users granted the special privileges TAPE-LBL or TAPE-BLP is not strictly controlled and limited to systems programmer and operations personnel, this is a finding.'
  desc 'fix', 'The ISSO will ensure Logonids with the TAPE-LBL or TAPE-BLP are kept to a minimum and are controlled and documented.

Review all LOGONIDs with these attributes. 

Tape label bypass (BLP) privileges will be restricted at the user level. Specify one of the following two logonid privileges to grant a user access to BLP processing:

User LID Record:
TAPE-LBL
TAPE-BLP

It is possible to grant selected programs to bypass tape label processing regardless of the BLP related privilege of the logonid executing the program. This capability will not be used due to the requirement that accounting of BLP processing be done at the user level. Do not utilize the GSO BLPPGM record.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25110r504446_chk'
  tag severity: 'medium'
  tag gid: 'V-223437'
  tag rid: 'SV-223437r533198_rule'
  tag stig_id: 'ACF2-ES-000160'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25098r504447_fix'
  tag 'documentable'
  tag legacy: ['V-97571', 'SV-106675']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
