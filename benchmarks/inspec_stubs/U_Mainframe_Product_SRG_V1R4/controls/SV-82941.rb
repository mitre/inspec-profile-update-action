control 'SV-82941' do
  title 'The Mainframe Product must prevent the execution of prohibited mobile code.'
  desc 'Decisions regarding the employment of mobile code within organizational information systems are based on the potential for the code to cause damage to the system if used maliciously. 

Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

Actions enforced before executing mobile code include, for example, prompting users prior to opening email attachments and disabling automatic execution.

Usage restrictions and implementation guidance apply to both the selection and use of mobile code installed, downloaded, or executed on all endpoints (e.g., servers, workstations, and smart phones). This requirement applies to applications that execute, evaluate, or otherwise process mobile code (e.g., web applications, browsers, and anti-virus applications).'
  desc 'check', 'If the Mainframe Product has no function or capability for mobile code use, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to prevent the execution of prohibited mobile code, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to prevent the execution of prohibited mobile code.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68983r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68451'
  tag rid: 'SV-82941r1_rule'
  tag stig_id: 'SRG-APP-000112-MFP-000280'
  tag gtitle: 'SRG-APP-000112-MFP-000280'
  tag fix_id: 'F-74567r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
