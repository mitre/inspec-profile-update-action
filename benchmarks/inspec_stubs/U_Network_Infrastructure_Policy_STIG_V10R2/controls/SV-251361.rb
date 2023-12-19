control 'SV-251361' do
  title 'Dynamic Host Configuration Protocol (DHCP) audit and event logs must record sufficient forensic data to be stored online for thirty days and offline for one year.'
  desc 'In order to identify and combat IP address spoofing, it is highly recommended that the DHCP server logs MAC addresses and hostnames on the DHCP server, in addition to standard data such as IP address and date/time.'
  desc 'check', 'Verify the DHCP audit and event logs include hostnames and MAC addresses of all clients, in addition to IP address and date/time.  Also, validate logs are kept online for thirty days and offline for one year.

If the logs do not include hostnames and MAC addresses along with the IP address and date/time, or if the logs are not kept online for thirty days and offline for one year, this is a finding.'
  desc 'fix', 'Configure the DHCP audit and event logs to log hostname and MAC addresses, in addition to IP address and date/time.

Store the logs for a minimum of thirty days online and then offline for one year.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54796r808531_chk'
  tag severity: 'medium'
  tag gid: 'V-251361'
  tag rid: 'SV-251361r809044_rule'
  tag stig_id: 'NET0198'
  tag gtitle: 'NET0198'
  tag fix_id: 'F-54749r808532_fix'
  tag 'documentable'
  tag legacy: ['V-8099', 'SV-8585']
  tag cci: ['CCI-001902']
  tag nist: ['AU-10 (1) (b)']
end
