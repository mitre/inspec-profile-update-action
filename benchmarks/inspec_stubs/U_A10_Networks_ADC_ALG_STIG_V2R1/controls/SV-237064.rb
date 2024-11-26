control 'SV-237064' do
  title 'The A10 Networks ADC must be a FIPS-compliant version.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

FIPS compliance is mandated for many functions of network devices. The A10 Networks ADC platforms are either FIPS-compliant versions or non-compliant versions. It is necessary to deploy the FIPS-compliant versions of the model(s). FIPS versions are identified by the designation "FIPS" in the stock keeping unit (SKU).'
  desc 'check', 'The following command shows the version of ACOS used and other related information:
show version

If the output does not include "Platform features: fips", this is a finding.'
  desc 'fix', 'Verify that the units deployed are the FIPS-compliant versions. This is identified by the designation "FIPS" in the stock keeping unit (SKU).'
  impact 0.7
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40283r639637_chk'
  tag severity: 'high'
  tag gid: 'V-237064'
  tag rid: 'SV-237064r639639_rule'
  tag stig_id: 'AADC-AG-000157'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-40246r639638_fix'
  tag 'documentable'
  tag legacy: ['SV-82519', 'V-68029']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
