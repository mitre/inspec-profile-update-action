control 'SV-82939' do
  title 'The Mainframe Product must prevent the download of prohibited mobile code.'
  desc 'Decisions regarding the employment of mobile code within organizational information systems are based on the potential for the code to cause damage to the system if used maliciously. 

Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

Usage restrictions and implementation guidance apply to both the selection and use of mobile code installed, downloaded, or executed on all endpoints (e.g., servers, workstations, and smart phones). This requirement applies to applications that execute, evaluate, or otherwise process mobile code (e.g., web applications, browsers, and anti-virus applications).'
  desc 'check', 'If the Mainframe Product has no function or capability for mobile code use, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to prevent the download of prohibited mobile code, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to prevent the download of prohibited mobile code.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68449'
  tag rid: 'SV-82939r1_rule'
  tag stig_id: 'SRG-APP-000209-MFP-000279'
  tag gtitle: 'SRG-APP-000209-MFP-000279'
  tag fix_id: 'F-74565r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
