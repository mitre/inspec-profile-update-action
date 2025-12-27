control 'SV-221893' do
  title 'The Oracle Linux operating system must not have unauthorized IP tunnels configured.'
  desc 'IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the Information System Security Officer (ISSO).'
  desc 'check', 'Verify the system does not have unauthorized IP tunnels configured.

Check to see if "libreswan" is installed with the following command:

# yum list installed libreswan
libreswan.x86-64 3.20-5.el7_4

If "libreswan" is installed, check to see if the "IPsec" service is active with the following command:

# systemctl status ipsec
ipsec.service - Internet Key Exchange (IKE) Protocol Daemon for IPsec
Loaded: loaded (/usr/lib/systemd/system/ipsec.service; disabled)
Active: inactive (dead)

If the "IPsec" service is active, check to see if any tunnels are configured in "/etc/ipsec.conf" and "/etc/ipsec.d/" with the following commands:

# grep -iw conn /etc/ipsec.conf /etc/ipsec.d/*.conf

If there are indications that a "conn" parameter is configured for a tunnel, ask the System Administrator if the tunnel is documented with the ISSO. 

If "libreswan" is installed, "IPsec" is active, and an undocumented tunnel is active, this is a finding.'
  desc 'fix', 'Remove all unapproved tunnels from the system, or document them with the ISSO.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23608r419751_chk'
  tag severity: 'medium'
  tag gid: 'V-221893'
  tag rid: 'SV-221893r603260_rule'
  tag stig_id: 'OL07-00-040820'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23597r419752_fix'
  tag 'documentable'
  tag legacy: ['SV-108629', 'V-99525']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
