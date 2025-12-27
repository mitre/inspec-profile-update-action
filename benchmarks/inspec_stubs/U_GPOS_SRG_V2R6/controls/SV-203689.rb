control 'SV-203689' do
  title 'The operating system must protect wireless access to the system using authentication of users and/or devices.'
  desc 'Allowing devices and users to connect to the system without first authenticating them allows untrusted access and can lead to a compromise or attack.

Wireless technologies include, for example, microwave, packet radio (UHF/VHF), 802.11x, and Bluetooth. Wireless networks use authentication protocols (e.g., EAP/TLS, PEAP), which provide credential protection and mutual authentication.

This requirement applies to those operating systems that control wireless devices.'
  desc 'check', 'Verify the operating system protects wireless access to the system using authentication of users and/or devices. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect wireless access to the system using authentication of users and/or devices.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3814r374954_chk'
  tag severity: 'medium'
  tag gid: 'V-203689'
  tag rid: 'SV-203689r379459_rule'
  tag stig_id: 'SRG-OS-000300-GPOS-00118'
  tag gtitle: 'SRG-OS-000300'
  tag fix_id: 'F-3814r374955_fix'
  tag 'documentable'
  tag legacy: ['V-57219', 'SV-71479']
  tag cci: ['CCI-001443']
  tag nist: ['AC-18 (1)']
end
