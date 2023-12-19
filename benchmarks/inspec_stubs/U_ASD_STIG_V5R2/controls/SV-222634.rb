control 'SV-222634' do
  title 'The application services and interfaces must be compatible with and ready for IPv6 networks.'
  desc 'If the application has not been upgraded to execute on an IPv6-only network, there is a possibility the application will not execute properly, and as a result, a denial of service could occur.

In order to operate on an IPV6 network, the application must be capable of making IPV6 compatible network socket calls.'
  desc 'check', 'Verify the application environment is compliant with all DoD IPv6 Standards Profile for IPv6 Capable Products guidance for servers.

If the application environment is not compliant with all DoD IPv6 Standards Profile for IPv6 Capable Products guidance for servers, this is a finding.'
  desc 'fix', 'Design application to be compliant with all Department of Defense (DoD) Information Technology Standards Registry (DISR) IPv6 profiles.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24304r493810_chk'
  tag severity: 'medium'
  tag gid: 'V-222634'
  tag rid: 'SV-222634r849507_rule'
  tag stig_id: 'APSC-DV-003030'
  tag gtitle: 'SRG-APP-000387'
  tag fix_id: 'F-24293r493811_fix'
  tag 'documentable'
  tag legacy: ['SV-84969', 'V-70347']
  tag cci: ['CCI-002853']
  tag nist: ['CP-11']
end
