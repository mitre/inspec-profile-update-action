control 'SV-223440' do
  title 'IBM z/OS Libraries included in the system REXXLIB concatenation must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Refer to AXRxx member of PARMLIB 
For each REXXLIB ADD statement 

If the ESM data set rules for libraries in the REXXLIB concatenation restrict WRITE or greater access to only z/OS systems programming personnel, this is not a finding.

If the ESM data set rules for libraries in the REXXLIB concatenation restrict READ access to the following, this is not a finding.

Appropriate Started Tasks
Auditors
The user-id defined in PARMLIB member AXR00 AXRUSER(user-id)

If the ESM data set rules for libraries in the REXXLIB concatenation specify that all (i.e., failures and successes) WRITE or greater access will be logged, this is not a finding.'
  desc 'fix', 'Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to protect APF Authorized Libraries. 

Configure ESM data set rules to limit WRITE or greater access to libraries included in the system REXXLIB concatenation to system programmers only.
Configure ESM data set rules allow READ access to only appropriate Started Tasks and Auditors.
Configure ESM data set rules to log UPDATE and/or ALTER access (i.e., successes and failures).'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25113r504452_chk'
  tag severity: 'high'
  tag gid: 'V-223440'
  tag rid: 'SV-223440r853504_rule'
  tag stig_id: 'ACF2-ES-000190'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25101r504453_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-106681', 'V-97577']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
