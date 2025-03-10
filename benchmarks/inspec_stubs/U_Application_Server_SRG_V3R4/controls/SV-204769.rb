control 'SV-204769' do
  title 'The application server must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Fail-secure is a condition achieved by the application server in order to ensure that in the event of an operational failure, the system does not enter into an unsecure state where intended security properties no longer hold.  Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption of mission-essential processes.'
  desc 'check', 'Review application server documentation and configuration to determine if the application server fails to a secure state if system initialization fails, shutdown fails, or aborts fail.

If the application server cannot be configured to fail securely, this is a finding.'
  desc 'fix', 'Configure the application server to fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4889r282954_chk'
  tag severity: 'medium'
  tag gid: 'V-204769'
  tag rid: 'SV-204769r879640_rule'
  tag stig_id: 'SRG-APP-000225-AS-000166'
  tag gtitle: 'SRG-APP-000225'
  tag fix_id: 'F-4889r282955_fix'
  tag 'documentable'
  tag legacy: ['V-57553', 'SV-71829']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
