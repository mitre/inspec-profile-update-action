control 'SV-250450' do
  title 'Android 12 devices must be configured to enable Common Criteria Mode (CC Mode).'
  desc 'The CC Mode feature is a superset of other features and behavioral changes that are mandatory MDFPP requirements. If CC mode is not implemented the device will not be operating in the NIAP-certified compliant CC Mode of operation.

CC Mode implements the following behavioral/functional changes: how the Bluetooth and Wi-Fi keys are stored using different types of encryption.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the managed Google Android 12 configuration settings to confirm CC mode is enabled. 
 
This procedure is performed on the EMM console.
 
COBO and COPE:

1. Open Device owner management.
2. Verify that "Enable Common Criteria mode" is toggled to ON.

If CC mode is not enabled, this is a finding.'
  desc 'fix', 'Configure the Google Android 12 device to implement CC Mode. 
 
On the EMM console:

COBO and COPE:

1. Open Device owner management.
2. Toggle "Enable Common Criteria mode" to ON.'
  impact 0.3
  ref 'DPMS Target Google Android 12 COPE'
  tag check_id: 'C-53885r796856_chk'
  tag severity: 'low'
  tag gid: 'V-250450'
  tag rid: 'SV-250450r802698_rule'
  tag stig_id: 'GOOG-12-011000'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-53839r796857_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
