control 'SV-35085' do
  title 'Inetd or xinetd logging/tracing must be enabled.'
  desc 'Inetd or xinetd logging and tracing allows the system administrators to observe the IP addresses connecting to their machines and to observe what network services are being sought. This provides valuable information when trying to find the source of malicious users and potential malicious users.'
  desc 'check', '# ps -ef | grep -v grep | egrep -i "inetd|xinetd"

If the -l logging parameter is not used, this is a finding.

If the (x)inetd process is not running, this is not a finding.'
  desc 'fix', 'Edit the (x)inetd startup script to include the -l parameter 
for the internet daemon process.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36533r1_chk'
  tag severity: 'low'
  tag gid: 'V-1011'
  tag rid: 'SV-35085r1_rule'
  tag stig_id: 'GEN003800'
  tag gtitle: 'GEN003800'
  tag fix_id: 'F-31897r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECSC-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
