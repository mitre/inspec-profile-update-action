control 'SV-71477' do
  title 'The operating system must protect wireless access to and from the system using encryption.'
  desc 'Allowing devices and users to connect to or from the system without first authenticating them allows untrusted access and can lead to a compromise or attack. Since wireless communications can be intercepted, it is necessary to use encryption to protect the confidentiality of information in transit.

Wireless technologies include, for example, microwave, packet radio (UHF/VHF), 802.11x, and Bluetooth. Wireless networks use authentication protocols (e.g., EAP/TLS, PEAP), which provide credential protection and mutual authentication.

This requirement applies to those operating systems that control wireless devices.'
  desc 'check', 'Verify the operating system protects wireless access to and from the system using encryption. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect wireless access to and from the system using encryption.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57217'
  tag rid: 'SV-71477r1_rule'
  tag stig_id: 'SRG-OS-000299-GPOS-00117'
  tag gtitle: 'SRG-OS-000299-GPOS-00117'
  tag fix_id: 'F-62135r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001444']
  tag nist: ['AC-18 (1)']
end
