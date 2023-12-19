control 'SV-234519' do
  title 'The UEM server must verify the digital signature of software before installation and alert the Information System Security Officer (ISSO), Information System Security Manager (ISSM), and other designated personnel if unauthorized software is detected.'
  desc 'Unauthorized software not only increases risk by increasing the number of potential vulnerabilities, it also can contain malicious code. Sending an alert (in real time) when unauthorized software is detected allows designated personnel to take action on the installation of unauthorized software.

This requirement applies to configuration management applications or similar types of applications designed to manage system processes and configurations (e.g., HBSS and software wrappers). 

Satisfies:FPT_TUD_EXT.1.3'
  desc 'check', 'Verify the UEM server verifies the digital signature of software before installation and alert the ISSM, ISSO, and other designated personnel if unauthorized software is detected.

If the UEM server does not verify the digital signature of software before installation and alert the ISSM, ISSO, and other designated personnel if unauthorized software is detected, this is a finding.'
  desc 'fix', 'Configure the UEM server to verify the digital signature of software before installation and alert the ISSM, ISSO, and other designated personnel if unauthorized software is detected.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37704r851585_chk'
  tag severity: 'medium'
  tag gid: 'V-234519'
  tag rid: 'SV-234519r879750_rule'
  tag stig_id: 'SRG-APP-000377-UEM-000247'
  tag gtitle: 'SRG-APP-000377'
  tag fix_id: 'F-37669r615201_fix'
  tag 'documentable'
  tag cci: ['CCI-001811']
  tag nist: ['CM-11 (1)']
end
