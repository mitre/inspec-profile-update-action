control 'SV-239977' do
  title 'The Cisco ASA remote access VPN server must be configured to generate unique session identifiers using a FIPS-validated Random Number Generator (RNG) based on the Deterministic Random Bit Generators (DRBG) algorithm.'
  desc 'Both IPsec and TLS gateways use the RNG to strengthen the security of the protocols. Using a weak RNG will weaken the protocol and make it more vulnerable.

Use of a FIPS validated RNG that is not DRGB mitigates to a CAT III.'
  desc 'check', 'Review the ASA configuration to verify that FIPS mode has been enabled as shown in the example below.

ASA Version x.x
!
hostname  ASA1
fips enable 

If the ASA is not configured to be enabled in FIPS mode, this is a finding.'
  desc 'fix', 'Configure the ASA to have FIPS-mode enabled as shown in the example below.

ASA1(config)# fips enable 
ASA1(config)# end

Note: FIPS mode change will not take effect until the configuration is saved and the device rebooted.'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43210r666335_chk'
  tag severity: 'medium'
  tag gid: 'V-239977'
  tag rid: 'SV-239977r666337_rule'
  tag stig_id: 'CASA-VN-000610'
  tag gtitle: 'SRG-NET-000234-VPN-000810'
  tag fix_id: 'F-43169r666336_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
