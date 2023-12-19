control 'SV-204760' do
  title 'The application server must identify prohibited mobile code.'
  desc 'Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

Mobile code technologies include: Java, JavaScript, ActiveX, PDF, Postscript, Shockwave movies, Flash animations, and VBScript. Usage restrictions and implementation guidance apply to both the selection and use of mobile code installed on organizational servers and mobile code downloaded and executed on individual workstations.

Application servers must meet policy requirements regarding the deployment and/or use of mobile code. This includes digitally signing applets in order to provide a means for the client to establish application authenticity and prohibit unauthorized code from being used.'
  desc 'check', 'Review the application server configuration to determine if the application server is configured to identify prohibited mobile code.

If the application server is not configured to identify prohibited mobile code, this is a finding.'
  desc 'fix', 'Configure the application server to identify prohibited mobile code.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4880r282927_chk'
  tag severity: 'medium'
  tag gid: 'V-204760'
  tag rid: 'SV-204760r508029_rule'
  tag stig_id: 'SRG-APP-000206-AS-000145'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-4880r282928_fix'
  tag 'documentable'
  tag legacy: ['V-57547', 'SV-71823']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
