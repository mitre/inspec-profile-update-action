control 'SV-206455' do
  title 'The Central Log Server must be configured to perform analysis of log records across multiple devices and hosts in the enclave that can be reviewed by authorized individuals.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis to allow the organization to identify and respond to potential incidents in a proficient manner. If the application does not provide the ability to centrally review the application logs, forensic analysis is negatively impacted.

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and event notification difficult to implement and manage, particularly when the system or application has multiple logging components written to different locations or systems.

Automated mechanisms for centralized reviews and analyses include, for example, Security Information and Event Management (SIEM) products.'
  desc 'check', 'Examine the configuration.

Verify the system is configured to perform analysis of log records across multiple devices and hosts in the enclave that can be reviewed by authorized individuals.

If the Central Log Server is not configured to perform analysis of log records across multiple devices and hosts in the enclave that can be reviewed by authorized individuals, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to perform analysis of log records across multiple devices and hosts in the enclave that can be reviewed by authorized individuals.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6715r285609_chk'
  tag severity: 'low'
  tag gid: 'V-206455'
  tag rid: 'SV-206455r395808_rule'
  tag stig_id: 'SRG-APP-000111-AU-000150'
  tag gtitle: 'SRG-APP-000111'
  tag fix_id: 'F-6715r285610_fix'
  tag 'documentable'
  tag legacy: ['SV-95833', 'V-81119']
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
