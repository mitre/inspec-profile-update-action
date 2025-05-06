control 'SV-20177' do
  title 'Bluetooth peripherals must conform to the DoD Bluetooth Peripheral Device Security Requirements Specification.'
  desc 'Sensitive unclassified voice and data communications could be intercepted and exposed if required security controls are not used.'
  desc 'check', 'Ask the IAO for documentation verifying Bluetooth peripherals (e.g., headsets) used by personnel at the site conform to the DoD Bluetooth Peripheral Device Security Requirements Specification (i.e., verification from NSA, DISA, or a DoD test agency). The specification is found at http://iase.disa.mil/stigs/net_perimeter/wireless/smartphone.html and http://www.nsa.gov/ia/_files/wireless/BlueToothDoc.pdf.'
  desc 'fix', 'Procure Bluetooth headsets that conform to the DoD Bluetooth Peripheral Device Security Requirements Specification.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-22301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-18619'
  tag rid: 'SV-20177r1_rule'
  tag stig_id: 'WIR0405'
  tag gtitle: 'Bluetooth peripherals security'
  tag fix_id: 'F-34125r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECCT-1'
end
