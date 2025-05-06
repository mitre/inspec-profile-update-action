control 'SV-38951' do
  title 'Inetd or xinetd logging/tracing must be enabled.'
  desc 'Inetd or xinetd logging and tracing allows the system administrators to observe the IP addresses that are connecting to their machines and to observe what network services are being sought.  This provides valuable information when trying to find the source of malicious users and potential malicious users.'
  desc 'check', 'Determine if inetd or xinetd has logging or tracing enabled. 

# ps -ef |grep inetd |grep -e "-d" 

If no results are returned, this is a finding.'
  desc 'fix', %q(Edit the inetd startup script to contain the "-d" parameter for the inetd process.

#vi /etc/rc.tcpip

# chssys -s inetd -a '-d')
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38287r2_chk'
  tag severity: 'low'
  tag gid: 'V-1011'
  tag rid: 'SV-38951r1_rule'
  tag stig_id: 'GEN003800'
  tag gtitle: 'GEN003800'
  tag fix_id: 'F-31831r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
