control 'SV-207437' do
  title 'The VMM must protect wireless access to the system using encryption.'
  desc 'Allowing devices and users to connect to the system without first authenticating them allows untrusted access and can lead to a compromise or attack. Since wireless communications can be intercepted, it is necessary to use encryption to protect the confidentiality of information in transit.

Wireless technologies include, for example, microwave, packet radio (UHF/VHF), 802.11x, and Bluetooth. Wireless networks use authentication protocols (e.g., EAP/TLS, PEAP), which provide credential protection and mutual authentication.

This requirement applies to those VMMs that control wireless devices.'
  desc 'check', 'Verify the VMM protects wireless access to the system using encryption.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to protect wireless access to the system using encryption.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7694r365721_chk'
  tag severity: 'medium'
  tag gid: 'V-207437'
  tag rid: 'SV-207437r379456_rule'
  tag stig_id: 'SRG-OS-000299-VMM-001060'
  tag gtitle: 'SRG-OS-000299'
  tag fix_id: 'F-7694r365722_fix'
  tag 'documentable'
  tag legacy: ['V-57075', 'SV-71335']
  tag cci: ['CCI-001444']
  tag nist: ['AC-18 (1)']
end
