control 'SV-234409' do
  title 'The UEM server must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Applications or systems that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption of mission-essential processes. 

In general, application security mechanisms should be designed so that a failure will follow the same execution path as disallowing the operation. For example, security methods, such as isAuthorized(), isAuthenticated(), and validate(), should all return false if there is an exception during processing. If security controls can throw exceptions, they must be very clear about exactly what that condition means. 

Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations. 

Satisfies:FPT_TST_EXT.1.2'
  desc 'check', 'Verify the UEM server fails to a secure state if system initialization fails, shutdown fails, or aborts fail.

If the UEM server does not fail to a secure state if system initialization fails, shutdown fails, or aborts fail, this is a finding.'
  desc 'fix', 'Configure the UEM server to fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37594r614237_chk'
  tag severity: 'medium'
  tag gid: 'V-234409'
  tag rid: 'SV-234409r617355_rule'
  tag stig_id: 'SRG-APP-000225-UEM-000136'
  tag gtitle: 'SRG-APP-000225'
  tag fix_id: 'F-37559r614238_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
