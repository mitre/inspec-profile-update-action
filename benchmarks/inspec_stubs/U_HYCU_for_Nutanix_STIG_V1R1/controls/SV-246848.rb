control 'SV-246848' do
  title 'The network device must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.'
  desc 'check', "The HYCU firewall is, by default, locked and enabled. Only the required/necessary services and ports are running on the HYCU Server.

Verify the firewall is running by executing the following command:
sudo firewall-cmd --state

If the service is not running, this is a finding.

Determine which services and ports are open by executing the following command: 
sudo firewall-cmd --list-all

Output should show following two lines:
'services: cockpit dhcpv6-client iscsi-target samba ssh'
'ports: 8443/tcp'

If more services than these are open, this is a finding."
  desc 'fix', 'Enable the firewall by logging on to the HYCU console and executing the following commands:
sudo systemctl enable firewalld

sudo systemctl start firewalld'
  impact 0.7
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50280r768206_chk'
  tag severity: 'high'
  tag gid: 'V-246848'
  tag rid: 'SV-246848r768208_rule'
  tag stig_id: 'HYCU-CM-000004'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-50234r768207_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
