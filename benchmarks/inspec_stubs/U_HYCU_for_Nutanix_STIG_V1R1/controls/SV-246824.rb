control 'SV-246824' do
  title 'The HYCU virtual machine must enforce approved authorizations for controlling the flow of management information within the network device based on information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data.'
  desc 'check', "By default, HYCU firewall is locked and enabled. The firewall only permits DHCP, SMB, and access to the web UI port 8443.

Verify the firewall is running by executing the following command:
sudo firewall-cmd --state

If service is not running, this is a finding.

Determine which services and ports are open by executing the following command:
sudo firewall-cmd --list-all

Output should show the following two lines:
'services: cockpit dhcpv6-client iscsi-target samba ssh'
'ports: 8443/tcp'

If more services than those listed above are open, this is a finding."
  desc 'fix', 'Enable the firewall by executing the following commands:
sudo systemctl enable firewalld

sudo systemctl start firewalld'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50256r768134_chk'
  tag severity: 'medium'
  tag gid: 'V-246824'
  tag rid: 'SV-246824r768136_rule'
  tag stig_id: 'HYCU-AC-000006'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-50210r768135_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
