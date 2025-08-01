control 'SV-207360' do
  title 'The VMM must support the capability to centrally review and analyze audit records from multiple components within the system.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the VMM does not provide the ability to centrally review the VMM logs, forensic analysis is negatively impacted.

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system has multiple logging components writing to different locations or systems.

To support the centralized capability, the VMM must be able to provide the information in a format that can be extracted and used, allowing the application performing the centralization of the log records to meet this requirement.'
  desc 'check', 'Verify the VMM supports the capability to centrally review and analyze audit records from multiple components within the system. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to support the capability to centrally review and analyze audit records from multiple components within the system.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7617r365490_chk'
  tag severity: 'medium'
  tag gid: 'V-207360'
  tag rid: 'SV-207360r378640_rule'
  tag stig_id: 'SRG-OS-000051-VMM-000230'
  tag gtitle: 'SRG-OS-000051'
  tag fix_id: 'F-7617r365491_fix'
  tag 'documentable'
  tag legacy: ['SV-71157', 'V-56897']
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
