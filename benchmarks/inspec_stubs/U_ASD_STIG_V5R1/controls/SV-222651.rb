control 'SV-222651' do
  title 'The changes to the application must be assessed for IA and accreditation impact prior to implementation.'
  desc 'When changes are made to an application, either in the code or in the configuration of underlying components such as the OS or the web or application server, there is the potential for security vulnerabilities to be opened up on the system.

IA assessment of proposed changes is necessary to verify security integrity is maintained within the application.'
  desc 'check', 'Interview the application and system administrators and determine if changes to the application are assessed for IA impact prior to implementation.

Review the CCB process documentation to ensure potential changes to the application are evaluated to determine impact. An informal group may be tasked with impact assessment of upcoming version changes.

If IA impact analysis is not performed, this is a finding.'
  desc 'fix', 'Review IA impact to the system prior to implementing changes.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24321r493861_chk'
  tag severity: 'medium'
  tag gid: 'V-222651'
  tag rid: 'SV-222651r508029_rule'
  tag stig_id: 'APSC-DV-003200'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24310r493862_fix'
  tag 'documentable'
  tag legacy: ['V-70381', 'SV-85003']
  tag cci: ['CCI-003173', 'CCI-000366']
  tag nist: ['SA-11 b', 'CM-6 b']
end
