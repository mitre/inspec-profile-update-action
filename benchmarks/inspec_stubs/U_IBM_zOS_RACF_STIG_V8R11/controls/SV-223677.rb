control 'SV-223677' do
  title 'IBM z/OS libraries included in the system REXXLIB concatenation must be properly protected.'
  desc 'Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Refer to AXRxx member of PARMLIB, for each REXXLIB ADD statement: 

If the ESM data set rules for libraries in the REXXLIB concatenation restrict WRITE or greater access to only z/OS systems programming personnel, this is not a finding.

If ESM dataset rules for libraries in the REXXLIB concatenation restrict GLOBAL read access, this is not a finding.

If ESM data set rules for libraries in the REXXLIB concatenating restrict WRITE or Greater access to z/OS system Programmers, this is not a finding.

If the ESM data set rules for libraries in the REXXLIB concatenation restrict READ access to the following, this is not a finding.

-Appropriate Started Tasks
-Auditors
-User-id defined in PARMLIB member AXR00 AXRUSER(user-id)

If the ESM data set rules for libraries in the REXXLIB concatenation specify that all (i.e., failures and successes) WRITE or greater access will be logged, this is not a finding.'
  desc 'fix', 'Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to protect APF Authorized Libraries. 

Configure ESM dataset rules to limit WRITE or greater access to libraries included in the system REXXLIB concatenation to system programmers only.

Configure ESM dataset rules allow READ access to only appropriate Started Tasks and Auditors.

Configure ESM dataset rules to log UPDATE and/or ALTER access (i.e., successes and failures).'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25350r767079_chk'
  tag severity: 'high'
  tag gid: 'V-223677'
  tag rid: 'SV-223677r853582_rule'
  tag stig_id: 'RACF-ES-000290'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25338r767080_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98059', 'SV-107163']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
