control 'SV-242243' do
  title 'The TippingPoint TPS must have FIPS Mode enforced.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not validated and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.'
  desc 'check', 'In the SMS client, verify the TPS FIPS Mode is enabled. 

1. For TPS, click Devices, All Devices, and the subject device hostname. 
2. Click FIPS Settings and ensure the FIPS Mode is selected.

If the TPS is not in FIPS mode, this is a finding.'
  desc 'fix', 'In the SMS client, enable the TPS FIPS Mode.

1. For TPS, click Devices, All Devices, and the subject device hostname.
2. Click FIPS Settings, then check enabled. This must be done in the approved change window, as the TPS will reboot.'
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45518r754431_chk'
  tag severity: 'high'
  tag gid: 'V-242243'
  tag rid: 'SV-242243r754439_rule'
  tag stig_id: 'TIPP-NM-000300'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-45476r754383_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
