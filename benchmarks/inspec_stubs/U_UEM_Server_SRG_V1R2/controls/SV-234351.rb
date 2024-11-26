control 'SV-234351' do
  title 'The UEM server must limit privileges to change the software resident within software libraries.'
  desc 'If the application were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to applications with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs, which execute with escalated privileges. Only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications. 

Satisfies:FMT_SMR.1.1(1), FPT_TUD_EXT.1.2'
  desc 'check', 'Verify the UEM server limits privileges to change the software resident within software libraries.

If the UEM server does not limit privileges to change the software resident within software libraries, this is a finding.'
  desc 'fix', 'Configure the UEM server to limit privileges to change the software resident within software libraries.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37536r614063_chk'
  tag severity: 'medium'
  tag gid: 'V-234351'
  tag rid: 'SV-234351r879586_rule'
  tag stig_id: 'SRG-APP-000133-UEM-000078'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-37501r614064_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
