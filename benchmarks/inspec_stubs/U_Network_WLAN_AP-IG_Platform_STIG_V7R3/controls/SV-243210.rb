control 'SV-243210' do
  title 'WLAN components must be FIPS 140-2 or FIPS 140-3 certified and configured to operate in FIPS mode.'
  desc 'If the DoD WLAN components (WLAN AP, controller, or client) are not NIST FIPS 140-2/FIPS 140-3 (Cryptographic Module Validation Program, CMVP) certified, the WLAN system may not adequately protect sensitive unclassified DoD data from compromise during transmission.'
  desc 'check', 'Review the WLAN equipment specification and verify it is FIPS 140-2/3 (CMVP) certified for data in transit, including authentication credentials. Verify the component is configured to operate in FIPS mode.

If the WLAN equipment is not is FIPS 140-2/3 (CMVP) certified or is not configured to operate in FIPS mode, this is a finding.'
  desc 'fix', 'Use WLAN equipment that is FIPS 140-2/3 (CMVP) certified. Configure the component to operate in FIPS mode.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-IG Platform'
  tag check_id: 'C-46485r891315_chk'
  tag severity: 'medium'
  tag gid: 'V-243210'
  tag rid: 'SV-243210r891317_rule'
  tag stig_id: 'WLAN-NW-000600'
  tag gtitle: 'SRG-NET-000151'
  tag fix_id: 'F-46442r891316_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
