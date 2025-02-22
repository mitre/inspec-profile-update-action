control 'SV-60225' do
  title 'The AirWatch MDM Server device integrity validation component must use automated mechanisms to alert security personnel when the device has been jailbroken or rooted.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner.  The ability of an AirWatch MDM Server to detect "jailbreaking" or rooting of the device mitigates the potential for these breaches to have further consequences to the enterprise.

"Jailbreaking"/rooting refers to a mobile device where the security mechanisms of the hardware and OS of the device have been bypassed so the user has root access.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server device integrity validation component uses automated mechanisms to alert security personnel when the device has been "jailbroken" or rooted. If this function is not configured, this is a finding.

To verify Compliance Policy is set to detect "Jailbroken" or Rooted devices: (1) click "Menu" on top tool bar, (2) click "Compliance" under "Profiles and Policies" heading, and (3) click on the hyperlinked compliance policy title, and verify in presented menu that on the tab titled "Rules" that the appropriate setting is selected in the first drop-down box (for detecting "jailbroken"/rooted devices, this should read "Compromised Status"). (4) Click "Next". (5) On Actions tab, verify the correct Action to take is set (for notification, first drop-down box should read "Notify", second should read "Send Email to Administrator", and third should list applicable email addresses). (6) On Assignment tab, verify correct device types, users, or groups are assigned.'
  desc 'fix', 'Configure the AirWatch MDM Server device integrity validation component to use automated mechanisms to alert security personnel when the device has been "jailbroken" or rooted.

To set Compliance Policy for "Jailbroken" or Rooted device detection with notification action: (1) click "Add" from the top tool bar, and (2) click "Compliance Policy". On Rules tab, (3) select to match "All" or "Any" of the entered Rules, (4) select "Compromised Status" in first drop-down box, and (5) "Is Compromised" in second drop-down box. (6) Click the "Next" button. (7) On Actions tab, (8) select "Notify" in first drop-down box, (9) select "Send Email to Administrator" in second drop-down box, and (10) enter in applicable email addresses for notification in "To:" box. (11) Click "Next". (12) On Assignment tab, select device types, users, or groups to assign Policy to, and (13) click "Next". (14) View Summary for accuracy, and (15) click "Save and Assign".'
  impact 0.7
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50119r2_chk'
  tag severity: 'high'
  tag gid: 'V-47353'
  tag rid: 'SV-60225r1_rule'
  tag stig_id: 'ARWA-01-000238'
  tag gtitle: 'SRG-APP-237-MDM-175-MDIS'
  tag fix_id: 'F-51059r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001274']
  tag nist: ['SI-4 (12)']
end
