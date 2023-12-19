control 'SV-221868' do
  title 'The Oracle Linux operating system must enable an application firewall, if available.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.

'
  desc 'check', 'Verify the operating system enabled an application firewall.

Check to see if "firewalld" is installed with the following command:

# yum list installed firewalld
firewalld-0.3.9-11.el7.noarch.rpm

If the "firewalld" package is not installed, ask the System Administrator if another firewall application (such as iptables) is installed. 

If an application firewall is not installed, this is a finding. 

Check to see if the firewall is loaded and active with the following command:

# systemctl status firewalld
firewalld.service - firewalld - dynamic firewall daemon

Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)
Active: active (running) since Tue 2014-06-17 11:14:49 CEST; 5 days ago

If "firewalld" does not show a status of "loaded" and "active", this is a finding. 

Check the state of the firewall:

# firewall-cmd --state 
running

If "firewalld" does not show a state of "running", this is a finding.'
  desc 'fix', %q(Ensure the operating system's application firewall is enabled.

Install the "firewalld" package, if it is not on the system, with the following command:

# yum install firewalld

Start the firewall via "systemctl" with the following command:

# systemctl start firewalld)
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23583r419676_chk'
  tag severity: 'medium'
  tag gid: 'V-221868'
  tag rid: 'SV-221868r603260_rule'
  tag stig_id: 'OL07-00-040520'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23572r419677_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000480-GPOS-00231', 'SRG-OS-000480-GPOS-00232']
  tag 'documentable'
  tag legacy: ['SV-108579', 'V-99475']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
