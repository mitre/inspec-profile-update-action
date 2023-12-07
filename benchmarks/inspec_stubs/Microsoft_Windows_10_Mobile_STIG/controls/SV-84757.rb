control 'SV-84757' do
  title 'Windows 10 Mobile must be configured to implement the management setting: Disable the capability of the Cortana personal assistant A.I. to be functional when the device is locked.'
  desc 'When a mobile device is locked, there should be no access to its protected/sensitive data as it could enable unauthorized people with physical access to the device to bring up and view sensitive information. The Cortana personal assistant can perform a number of voice related queries and actions which can aid productivity but also allows some of its actions to be done while the device is locked. For example, even if the device is locked, if you can bring up the Cortana search page you can ask things like "show me my calendar" and that will bring up potentially sensitive information under lockscreen. Disabling this feature mitigates the exposure of potentially sensitive information that should remain secured when a device is locked.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the mobile device can still use Cortana voice control while it is locked. If feasible, use a spare device to determine if calling up Cortana to listen and respond to commands is possible while the device is locked.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device. It assumes you have an existing device timeout policy in place that will lock the device after a certain period.

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for "allow access to the Cortana personal assistant".
3. Verify that setting restriction is turned off/disallowed.

On the Windows 10 Mobile device:

1. Unlock the device.
2. Tap the "Search" button at the lower right of the device. 
3. Verify that when the search screen comes up that a message with "Sorry, but your company policy prevents me from working" appears at the top.

If the MDM does not have a policy setting enforced for "allow access to the Cortana personal assistant" or if when you tap the "Search" button on an unlocked device a message does not come up with the wording "Sorry, but your company policy prevents me from working", this is a finding.'
  desc 'fix', 'Configure the MDM system to require the "allow access to the Cortana personal assistant" policy be disabled for Windows 10 Mobile devices. 

Deploy the MDM policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70611r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70135'
  tag rid: 'SV-84757r1_rule'
  tag stig_id: 'MSWM-10-911102'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76371r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
