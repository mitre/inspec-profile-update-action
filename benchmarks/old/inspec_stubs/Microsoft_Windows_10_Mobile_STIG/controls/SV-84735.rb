control 'SV-84735' do
  title 'Windows 10 Mobile must enable all IP traffic (other than IP traffic required to establish the VPN connection) to flow through the IPsec VPN client or provide an interface to VPN applications for this purpose.'
  desc 'It is common for mobile devices to connect directly to wireless networks that DoD does not manage, including direct Internet access through the cellular service provider. This condition leaves the device vulnerable to attacks from those networks. It also prevents DoD from monitoring or filtering network traffic to or from the mobile device. This makes it more likely that users or application processes will have the ability to perform unauthorized activities or do so without detection. For example, the enterprise may have a filtering mechanism to prevent users from accessing certain websites. Directing all device IP traffic (other than traffic needed to establish the VPN connection) through a VPN client enables the enterprise to route and handle traffic appropriately based on DoD policy and IA objectives. This requirement is also related to verifying VPN split-tunneling is not enabled.

SFR ID: FDP_IFC_EXT.1.1'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if all IP traffic is enabled to flow through the IPsec VPN client or provide an interface to VPN applications for this purpose.

This validation procedure is performed only on the MDM administration console.

On the MDM administration console:

Ask the MDM administrator to verify that the site-specific VPN policy on the MDM console has been configured to require the "LockDown" setting which provides an always on forced tunnel configuration.

If the site-specific VPN profile on the MDM is not configured to require the VPN profile "LockDown" setting, this is a finding.'
  desc 'fix', 'Configure the site-specific VPN profile on the MDM to require the VPN profile "LockDown".

Note: A VPN profile using the LockDown configuration will become the authoritative VPN control as it mandates all traffic route through it. This overrides any other VPN profiles that are configured and only one Lockdown VPN profile should be configured.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70589r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70113'
  tag rid: 'SV-84735r1_rule'
  tag stig_id: 'MSWM-10-202901'
  tag gtitle: 'PP-MDF-202028'
  tag fix_id: 'F-76349r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
