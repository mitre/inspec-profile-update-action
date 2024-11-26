control 'SV-234667' do
  title 'The UEM server must be configured to allow authorized administrators to read all audit data from audit records on the server.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the application does not provide the ability to centrally review the application logs, forensic analysis is negatively impacted. 

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system or application has multiple logging components written to different locations or systems.

Automated mechanisms for centralized reviews and analyses include, for example, Security Information Management products. 

Satisfies:FAU_SAR.1.1 
Reference:PP-MDM-413000'
  desc 'check', 'Verify the UEM server allows authorized administrators to read all audit data from audit records on the server.

If the UEM server does not allow authorized administrators to read all audit data from audit records on the server, this is a finding.'
  desc 'fix', 'Configure the UEM server to allow authorized administrators to read all audit data from audit records on the server.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37852r615635_chk'
  tag severity: 'medium'
  tag gid: 'V-234667'
  tag rid: 'SV-234667r617355_rule'
  tag stig_id: 'SRG-APP-000516-UEM-000392'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37817r615636_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
