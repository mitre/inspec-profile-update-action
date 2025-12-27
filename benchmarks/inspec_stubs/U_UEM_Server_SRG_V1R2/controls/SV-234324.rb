control 'SV-234324' do
  title 'The UEM server must be configured to provide audit records in a manner suitable for the Authorized Administrators to interpret the information.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the application does not provide the ability to centrally review the application logs, forensic analysis is negatively impacted. 

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system or application has multiple logging components written to different locations or systems.

Automated mechanisms for centralized reviews and analyses include, for example, Security Information Management products. 

Satisfies:FAU_SAR.1.2 
Reference:PP-MDM-413050'
  desc 'check', 'Verify the UEM server provides audit records in a manner suitable for the Authorized Administrators to interpret the information.

If the UEM server does not provide audit records in a manner suitable for the Authorized Administrators to interpret the information, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to provide audit records in a manner suitable for the Authorized Administrators to interpret the information.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37509r613982_chk'
  tag severity: 'medium'
  tag gid: 'V-234324'
  tag rid: 'SV-234324r879559_rule'
  tag stig_id: 'SRG-APP-000089-UEM-000050'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-37474r613983_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
