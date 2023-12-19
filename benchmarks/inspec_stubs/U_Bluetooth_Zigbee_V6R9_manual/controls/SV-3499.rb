control 'SV-3499' do
  title 'If Bluetooth (or Zigbee) devices transmit unclassified DoD data communications, then they must use FIPS 140-2 validated cryptographic modules for data in transit, including digital voice communications.'
  desc 'FIPS validation provides assurance that the cryptographic modules are implemented correctly and resistant to compromise.  Failure to use FIPS 140-2 validated cryptographic modules makes it more likely that sensitive DoD data will be exposed to unauthorized people.'
  desc 'check', 'NOTE: This check also applies to Bluetooth voice and wireless USB (WUSB) devices. This check does not apply to Zigbee telemetry sensor data or other Zigbee data where the IAO has determined the data is not sensitive. 

- If the site uses Bluetooth (or Zigbee) for data or voice communications, check a sample (3-4) of Bluetooth (or Zigbee) enabled devices and note their make and model.  Examine the associated product documentation to determine if the device employs FIPS 140-2 validated cryptographic modules for data-in-transit, to include digital voice communications.  This should be accomplished by reviewing the relevant FIPS certificate in the product documentation or the NIST web site.

Mark as a finding if any Bluetooth (or Zigbee) device does have a FIPS 140-2 validated cryptographic module supporting encryption of data in transit.

Note: This requirement only applies to mobile devices that are expected to leave a DoD facility.  It does not apply to voice headsets for fixed location assets such as IP-based desk telephones.  No encryption or identification requirements are required for this use.'
  desc 'fix', 'Disable Bluetooth or procure Bluetooth devices that employ FIPS 140-2 validated cryptographic modules for data-in-transit.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-39029r4_chk'
  tag severity: 'medium'
  tag gid: 'V-3499'
  tag rid: 'SV-3499r2_rule'
  tag stig_id: 'WIR0400'
  tag gtitle: 'FIPS validation for Bluetooth data/voice'
  tag fix_id: 'F-3430r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECCT-1'
end
