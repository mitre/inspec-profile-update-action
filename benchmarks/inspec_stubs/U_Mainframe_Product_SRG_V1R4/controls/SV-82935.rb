control 'SV-82935' do
  title 'The Mainframe Product must identify prohibited mobile code.'
  desc 'Decisions regarding the employment of mobile code within applications are based on the potential for the code to cause damage to the system if used maliciously. 

Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

DoD has identified prohibited mobile code in DoDI 8552.01 as: all Category 1X mobile code, unsigned Category 1A mobile code, Category 2 mobile code that violates usage requirements, all Emerging Technologies mobile code (all mobile code technologies, systems, platforms, or languages whose capabilities and threat level have not yet undergone a risk assessment and been assigned to a risk category), and all mobile code that downloads via an email body or email attachment that executes automatically when the user opens the email body or attachment.

Usage restrictions and implementation guidance apply to both the selection and use of mobile code installed, downloaded, or executed on all endpoints (e.g., servers, workstations, and smart phones). This requirement applies to applications that execute, evaluate, or otherwise process mobile code (e.g., web applications, browsers, and anti-virus applications).'
  desc 'check', 'If the Mainframe Product has no function for the use of mobile code, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product does not identify mobile code in the installation, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to identify mobile code in the installation.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68445'
  tag rid: 'SV-82935r1_rule'
  tag stig_id: 'SRG-APP-000206-MFP-000277'
  tag gtitle: 'SRG-APP-000206-MFP-000277'
  tag fix_id: 'F-74561r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
