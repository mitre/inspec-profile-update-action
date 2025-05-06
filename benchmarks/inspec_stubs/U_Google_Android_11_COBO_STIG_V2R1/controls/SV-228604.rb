control 'SV-228604' do
  title 'Google Android 11 devices must be configured to enable Common Criteria Mode (CC Mode).'
  desc 'The CC Mode feature is a superset of other features and behavioral changes that are mandatory MDFPP requirements. If CC mode is not implemented the device will not be operating in the NIAP-certified compliant CC Mode of operation.

CC Mode implements the following behavioral/functional changes: how the Bluetooth and Wi-Fi keys are stored using different types of encryption.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm CC mode is enabled. 
 
This procedure is performed on the EMM console.
 
In the EMM management console, verify CC Mode has been enabled.

If CC mode is not enabled, this is a finding.'
  desc 'fix', 'Configure Google Android 11 device to implement CC Mode. 
 
On the EMM console, enable "CC Mode".'
  impact 0.3
  ref 'DPMS Target Google Android 11 COBO'
  tag check_id: 'C-30839r505637_chk'
  tag severity: 'low'
  tag gid: 'V-228604'
  tag rid: 'SV-228604r619923_rule'
  tag stig_id: 'GOOG-11-011100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30816r505638_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
