control 'SV-225125' do
  title 'The macOS system must be configured with Wi-Fi support software disabled.'
  desc 'Allowing devices and users to connect to or from the system without first authenticating them allows untrusted access and can lead to a compromise or attack. Since wireless communications can be intercepted, it is necessary to use encryption to protect the confidentiality of information in transit.

Wireless technologies include, for example, microwave, packet radio (UHF/VHF), 802.11x, and Bluetooth. Wireless networks use authentication protocols (e.g., EAP/TLS, PEAP), which provide credential protection and mutual authentication.

'
  desc 'check', 'If the system requires Wi-Fi to connect to an authorized network, this is not applicable.

To check if the Wi-Fi network device is disabled, run the following command:

/usr/bin/sudo /usr/sbin/networksetup -listallnetworkservices

A disabled device will have an asterisk in front of its name.

If the Wi-Fi device is missing this asterisk, this is a finding.'
  desc 'fix', 'To disable the Wi-Fi network device, run the following command:

/usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled "Wi-Fi" off'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26824r467543_chk'
  tag severity: 'medium'
  tag gid: 'V-225125'
  tag rid: 'SV-225125r610901_rule'
  tag stig_id: 'AOSX-15-000008'
  tag gtitle: 'SRG-OS-000299-GPOS-00117'
  tag fix_id: 'F-26812r467544_fix'
  tag satisfies: ['SRG-OS-000299-GPOS-00117', 'SRG-OS-000300-GPOS-00118', 'SRG-OS-000379-GPOS-00164']
  tag 'documentable'
  tag legacy: ['V-102665', 'SV-111627']
  tag cci: ['CCI-001443', 'CCI-001444', 'CCI-001967']
  tag nist: ['AC-18 (1)', 'AC-18 (1)', 'IA-3 (1)']
end
