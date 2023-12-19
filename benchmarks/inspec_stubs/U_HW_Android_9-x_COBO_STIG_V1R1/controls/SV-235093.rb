control 'SV-235093' do
  title 'On all Honeywell Mobility Edge Android Pie devices, cryptography must be configured to be in FIPS 140-2 validated mode.'
  desc 'Unapproved cryptographic algorithms cannot be relied upon to provide confidentiality or integrity, and DoD data could be compromised as a result. The Honeywell Android devices common vulnerabilities with cryptographic modules are those associated with poor implementation. FIPS 140-2 validation provides assurance that the relevant cryptography has been implemented correctly. FIPS 140-2 validation is also a strict requirement for use of cryptography in the Federal Government for protecting unclassified data.

SFR ID: FCS'
  desc 'check', 'Review Honeywell Android device configuration settings to determine if the mobile device is in FIPS enforce mode.

This validation procedure is performed on the Android Pie device.

On the Honeywell Android Pie device:

1. Open Settings >> Honeywell Settings >> FIPS Enforce Mode.
2. Verify the option of "FIPS Enforce Mode" is enabled.

If the option of "FIPS Enforce Mode" is disabled on the Honeywell Android Pie device, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android device to enable FIPS mode.

On the MDM console:
1. Ask the MDM Administrator to edit the following item in DeviceConfig.xml:
 Modify item: DeviceConfig >> HoneywellSetting >> EnforceOSFipsMode
 Value sample: 1: Enable OS FIPS mode; 0: Disable OS FIPS mode
2. In MDM console, the MDM Administrator will package this DeviceConfig.xml and push this package to the CN80G device.

On the Honeywell Android Pie device:
1. Open Settings >> Honeywell Settings >> FIPS Enforce Mode.
2. Enable FIPS Enforce mode.'
  impact 0.7
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38312r623104_chk'
  tag severity: 'high'
  tag gid: 'V-235093'
  tag rid: 'SV-235093r626530_rule'
  tag stig_id: 'HONW-09-008400'
  tag gtitle: 'PP-MDF-301010'
  tag fix_id: 'F-38275r623100_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
