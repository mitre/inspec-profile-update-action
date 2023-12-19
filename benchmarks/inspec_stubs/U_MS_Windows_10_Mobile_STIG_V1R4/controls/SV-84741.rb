control 'SV-84741' do
  title 'Windows 10 Mobile must be configured to disable all Bluetooth profiles except for HSP (Headset Profile), HFP (HandsFree Profile), and SPP (Serial Port Profile).'
  desc 'Some Bluetooth profiles provide the capability for remote transfer of sensitive DoD data without encryption or otherwise do not meet DoD IT security policies and therefore should be disabled. 

SFR ID: FMT_SMF_EXT.1.1 #20f'
  desc 'check', 'Review Windows 10 Mobile configuration settings to disable all Bluetooth profiles except for HSP (Headset Profile), HFP (HandsFree Profile), and SPP (Serial Port Profile). 

This validation procedure is performed only on the MDM administration console.

On the MDM administration console:

1. Ask the MDM administrator to verify the Bluetooth compliance policy.
2. Find the setting for restricting "Bluetooth Services Allowed" profiles.
3. Verify that HSP, HFP and SPP are the only Bluetooth profiles allowed in the Bluetooth policy. If the MDM console does not expose any UI controls for Bluetooth profiles a custom configuration value can used as shown here:

"{0000111E-0000-1000-8000-00805F9B34FB};{00001108-0000-1000-8000-00805F9B34FB};{00001101-0000-1000-8000-00805F9B34FB}"

If the MDM does not have a compliance policy that restricts Bluetooth profiles to just those allowed, this is a finding.'
  desc 'fix', 'Configure the MDM system to enforce a policy which configures the "Bluetooth Services Allowed" policy to restrict Bluetooth profiles to just HSP (Headset Profile), HFP (HandsFree Profile), and SPP (Serial Port Profile). 

Deploy the MDM policy to managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70595r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70119'
  tag rid: 'SV-84741r1_rule'
  tag stig_id: 'MSWM-10-500504'
  tag gtitle: 'PP-MDF-201027'
  tag fix_id: 'F-76355r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
