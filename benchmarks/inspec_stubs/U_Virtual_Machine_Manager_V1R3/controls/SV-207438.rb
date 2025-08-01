control 'SV-207438' do
  title 'The VMM must protect wireless access to the system using authentication of users and/or devices.'
  desc 'Allowing devices and users to connect to the system without first authenticating them allows untrusted access and can lead to a compromise or attack.

Wireless technologies include, for example, microwave, packet radio (UHF/VHF), 802.11x, and Bluetooth. Wireless networks use authentication protocols (e.g., EAP/TLS, PEAP), which provide credential protection and mutual authentication.

This requirement applies to those VMMs that control wireless devices.'
  desc 'check', 'Verify the VMM protects wireless access to the system using authentication of users and/or devices.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to protect wireless access to the system using authentication of users and/or devices.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7695r365724_chk'
  tag severity: 'medium'
  tag gid: 'V-207438'
  tag rid: 'SV-207438r379459_rule'
  tag stig_id: 'SRG-OS-000300-VMM-001070'
  tag gtitle: 'SRG-OS-000300'
  tag fix_id: 'F-7695r365725_fix'
  tag 'documentable'
  tag legacy: ['SV-71337', 'V-57077']
  tag cci: ['CCI-001443']
  tag nist: ['AC-18 (1)']
end
