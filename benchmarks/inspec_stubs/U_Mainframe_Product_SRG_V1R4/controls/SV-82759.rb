control 'SV-82759' do
  title 'The Mainframe Product must provide the capability to centrally review and analyze audit records from multiple components within the system.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the application does not provide the ability to centrally review the application logs, forensic analysis is negatively impacted. 

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system or application has multiple logging components written to different locations or systems.

Automated mechanisms for centralized reviews and analyses include, for example, Security Information Management products.'
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product has the capability to centrally review and analyze audit records from multiple components in the system. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to centrally review and analyze audit records from multiple components in the system.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68269'
  tag rid: 'SV-82759r1_rule'
  tag stig_id: 'SRG-APP-000111-MFP-000156'
  tag gtitle: 'SRG-APP-000111-MFP-000156'
  tag fix_id: 'F-74383r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
