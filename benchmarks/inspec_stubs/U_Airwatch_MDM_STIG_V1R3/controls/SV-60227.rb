control 'SV-60227' do
  title 'The AirWatch MDM Server device integrity validation component must identify the affected mobile device, severity of the finding, and provide a recommended mitigation.'
  desc 'One of the most significant indicators of an IA attack is modification of operating system files, device drivers, or security enforcement mechanisms.  An integrity verification capability or tool detects unauthorized modifications to files or permissions and either prevents further operation or reports its findings so an appropriate response can occur.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server device integrity validation component identifies the affected mobile device, severity of the finding, and provide a recommended mitigation. If this function is not configured, this is a finding.

Ensure Compliance detection for various Policies are properly set: (1) click "Menu" on top tool bar, (2) click "Compliance" under "Profiles and Policies" heading, and (3) click on the hyperlinked compliance policy title, and verify in presented menu that on the tab titled "Rules" that the appropriate setting is selected in the first drop-down box (for detecting "jailbroken"/rooted devices, this should read "Compromised Status"). (4) Click "Next". (5) On Actions tab, verify the correct Action to take is set (for notification, first drop-down box should read "Notify", second should read "Send Email to Administrator", and third should list applicable email addresses). (6) On Assignment tab, verify correct device types, users, or groups are assigned.'
  desc 'fix', 'Configure the AirWatch MDM Server device integrity validation component to identify the affected mobile device, severity of the finding, and provide a recommended mitigation.

To set Compliance Policies: (1) click "Add" from the top tool bar, and (2) click "Compliance Policy". On Rules tab, (3) select to match "All" or "Any" of the entered Rules, (4) in first drop-down box select applicable rule to be set, and (5) click "Next". (6) On Actions tab, select appropriate action to take (Administrator is able set escalation of Actions based on internal risk level decision). (7) Click "Next". (8) On Assignment tab, select device types, users, or groups to assign Policy to, and (9) click "Next". (10) View Summary for accuracy, and (11) click "Save and Assign".'
  impact 0.7
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50121r2_chk'
  tag severity: 'high'
  tag gid: 'V-47355'
  tag rid: 'SV-60227r1_rule'
  tag stig_id: 'ARWA-01-000246'
  tag gtitle: 'SRG-APP-262-MDM-180-MDIS'
  tag fix_id: 'F-51061r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001297']
  tag nist: ['SI-7']
end
