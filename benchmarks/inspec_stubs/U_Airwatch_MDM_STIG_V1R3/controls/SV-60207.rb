control 'SV-60207' do
  title 'The AirWatch MDM Server must be able to detect if the security policy has been modified, disabled, or bypassed on managed mobile devices.'
  desc 'If the security policy has been modified in an unauthorized manner, IA is severely degraded and a variety of further attacks are possible.  Detecting whether the security policy has been modified or disabled mitigates these risks.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server can detect if the security policy has been modified, disabled, or bypassed on managed mobile devices. If this function is not present, this is a finding.

To verify policies for the Compliance Engine, use the following procedure: (1) click "Menu" on top tool bar, (2) click "Compliance" under "Profiles and Policies" heading, and (3) click on applicable compliance policy. On Rules tab, verify the correct rule set for the applicable policy to be applied. (4) On Actions tab, verify the correct Action type to take Actionable Result is set. (5) On Assignment tab, verify correct device types, users, or groups are assigned.

(Note: for "jailbroken" or "rooted device" detection, verify "Compromised Status" and "Is Compromised" is selected on Rules tab.'
  desc 'fix', 'Configure the AirWatch MDM Server to detect if the security policy has been modified, disabled, or bypassed on managed mobile devices.

To establish policies for the Compliance Engine, use the following procedure: (1) click "Add" from the top tool bar, and (2) click "Compliance Policy". On Rules tab select the following: (1a) To Match "All" or "Any" of the entered Rules, (2a) Choose deviation to detect on devices, and (3a) click "Next". (3) On Actions tab, select the following: (a) Choose Action type to take (command), and (b) Actionable Result, and (c) click Next. (4) On Assignment tab select device types, users, or groups to assign Policy to, and (5) click "Next". (6) View Summary for accuracy, and (7) click Save and Assign.

(Note: for "jailbroken" or "rooted device" detection, select "Compromised Status" and "Is Compromised" on Rules tab.'
  impact 0.7
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50101r3_chk'
  tag severity: 'high'
  tag gid: 'V-47335'
  tag rid: 'SV-60207r1_rule'
  tag stig_id: 'ARWA-01-000150'
  tag gtitle: 'SRG-APP-137-MDM-151-MDM'
  tag fix_id: 'F-51041r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000372']
  tag nist: ['CM-6 (1)']
end
