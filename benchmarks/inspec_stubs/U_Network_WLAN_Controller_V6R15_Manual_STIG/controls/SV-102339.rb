control 'SV-102339' do
  title 'WLAN components must be FIPS 140-2 certified.'
  desc 'If the DoD WLAN components (WLAN AP, controller, or client) are not NIST FIPS 140-2 (Cryptographic Module Validation Program – CMVP) certified, the WLAN system may not adequately protect sensitive unclassified DoD data from compromise during transmission.'
  desc 'check', 'Review the WLAN equipment specification and verify it is FIPS 140-2 (CMVP) certified for data in transit, including authentication credentials.

If the WLAN equipment is not is FIPS 140-2 (CMVP) certified, this is a finding.'
  desc 'fix', 'Use WLAN equipment that is FIPS 140-2 (CMVP) certified.'
  impact 0.5
  ref 'DPMS Target WLAN Controller'
  tag check_id: 'C-91401r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92237'
  tag rid: 'SV-102339r1_rule'
  tag stig_id: 'WIR0115-3'
  tag gtitle: 'WLAN FIPS 140-2 Certified'
  tag fix_id: 'F-98445r1_fix'
  tag 'documentable'
end
