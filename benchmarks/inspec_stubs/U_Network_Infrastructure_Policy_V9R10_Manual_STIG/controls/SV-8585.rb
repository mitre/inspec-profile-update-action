control 'SV-8585' do
  title 'Dynamic Host Configuration Protocol (DHCP) audit and event logs must record hostnames and MAC addresses to be stored online for thirty days and offline for one year.'
  desc 'In order to identify and combat IP address spoofing, it is highly recommended that the DHCP server logs MAC addresses and hostnames on the DHCP server.'
  desc 'check', 'Verify the DHCP audit and event logs include hostnames and MAC addresses of all clients.  Also, validate logs are kept online for thirty days and offline for one year.

If the logs do not include hostnames and MAC addresses or if the logs are not kept online for thirty days and offline for one year, this is a finding.'
  desc 'fix', 'Configure the DHCP audit and event logs to log hostname and MAC addresses.

Store the logs for a minimum of thirty days online and then offline for one year.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-7480r3_chk'
  tag severity: 'low'
  tag gid: 'V-8099'
  tag rid: 'SV-8585r3_rule'
  tag stig_id: 'NET0198'
  tag gtitle: 'DHCP audit and event logs and info collected.'
  tag fix_id: 'F-7674r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001902']
  tag nist: ['AU-10 (1) (b)']
end
