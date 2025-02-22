control 'SV-209528' do
  title 'The macOS system must be configured with Wi-Fi support software disabled.'
  desc 'Allowing devices and users to connect to or from the system without first authenticating them allows untrusted access and can lead to a compromise or attack. Since wireless communications can be intercepted, it is necessary to use encryption to protect the confidentiality of information in transit.

Wireless technologies include, for example, microwave, packet radio (UHF/VHF), 802.11x, and Bluetooth. Wireless networks use authentication protocols (e.g., EAP/TLS, PEAP), which provide credential protection and mutual authentication.

'
  desc 'check', 'If the system requires Wi-Fi to connect to an authorized network, this is Not Applicable.

To check if the Wi-Fi network device is disabled, run the following command:

/usr/bin/sudo /usr/sbin/networksetup -listallnetworkservices

A disabled device will have an asterisk in front of its name.

If the Wi-Fi device is missing this asterisk, this is a finding.'
  desc 'fix', 'To disable the Wi-Fi network device, run the following command:

/usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled "Wi-Fi" off'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9779r282066_chk'
  tag severity: 'medium'
  tag gid: 'V-209528'
  tag rid: 'SV-209528r610285_rule'
  tag stig_id: 'AOSX-14-000008'
  tag gtitle: 'SRG-OS-000299-GPOS-00117'
  tag fix_id: 'F-9779r282067_fix'
  tag satisfies: ['SRG-OS-000299-GPOS-00117', 'SRG-OS-000300-GPOS-00118']
  tag 'documentable'
  tag legacy: ['SV-104939', 'V-95801']
  tag cci: ['CCI-001443', 'CCI-001444']
  tag nist: ['AC-18 (1)', 'AC-18 (1)']
end
