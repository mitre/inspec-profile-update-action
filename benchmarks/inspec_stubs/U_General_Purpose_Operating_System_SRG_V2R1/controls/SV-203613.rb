control 'SV-203613' do
  title 'The operating system must provide the capability to centrally review and analyze audit records from multiple components within the system.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the operating system does not provide the ability to centrally review the operating system logs, forensic analysis is negatively impacted.

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system has multiple logging components writing to different locations or systems.

To support the centralized capability, the operating system must be able to provide the information in a format that can be extracted and used, allowing the application performing the centralization of the log records to meet this requirement.'
  desc 'check', 'Verify the operating system provides the capability to centrally review and analyze audit records from multiple components within the system. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide the capability to centrally review and analyze audit records from multiple components within the system.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3738r557095_chk'
  tag severity: 'medium'
  tag gid: 'V-203613'
  tag rid: 'SV-203613r557097_rule'
  tag stig_id: 'SRG-OS-000051-GPOS-00024'
  tag gtitle: 'SRG-OS-000051'
  tag fix_id: 'F-3738r557096_fix'
  tag 'documentable'
  tag legacy: ['V-56665', 'SV-70925']
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
