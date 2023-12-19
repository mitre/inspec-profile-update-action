control 'SV-75339' do
  title 'The Arista Multilayer Switch must, at a minimum, off-load audit records for interconnected systems in real time.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Check the network device configuration to determine if the device off-loads audit records onto a different system or media than the system being audited. 

If the device does not off-load audit records onto a different system or media, this is a finding.

Review the configuration for the "logging host [a.b.c.d]" statement. Execute a "show logging" to verify logging host status.'
  desc 'fix', 'Configure the network device to off-load interconnected systems in real time and off-load standalone systems weekly.

Arista EOS logs can be exported to, including by a regular syslog server.

Configuration Example: 

switch(config)#logging host[ a.b.c.d]
switch(config)#logging trap informational'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60881'
  tag rid: 'SV-75339r1_rule'
  tag stig_id: 'AMLS-NM-000400'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-66593r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
