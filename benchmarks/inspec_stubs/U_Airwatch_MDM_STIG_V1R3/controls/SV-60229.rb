control 'SV-60229' do
  title 'The AirWatch MDM Server device integrity validation component must base recommended mitigations for findings on the identified risk level of the finding.'
  desc 'One of the most significant indicators of an IA attack is modification of operating system files, device drivers, or security enforcement mechanisms.  An integrity verification capability or tool detects unauthorized modifications to files or permissions and either prevents further operation or reports its findings so an appropriate response can occur.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server device integrity validation component bases recommended mitigations for findings on the identified risk level of the finding. If this function is not configured, this is a finding.

Ensure Compliance detection escalations for various Policies are properly set: (1) click "Menu" on top tool bar, (2) click "Compliance" under "Profiles and Policies" heading, and (3) click on the hyperlinked compliance policy title, and verify in presented menu that on the tab titled "Rules" that the appropriate setting is selected in the first drop-down box (for detecting "jailbroken"/rooted devices, this should read "Compromised Status"). (4) Click "Next". (5) On Actions tab, verify the correct Action to take is selected (Administrator is able to set escalation of Actions based on internal risk level decision). (6) On Assignment tab, verify correct device types, users, or groups are assigned.'
  desc 'fix', 'Configure the AirWatch MDM Server device integrity validation component to base recommended mitigations for findings on the identified risk level of the finding.

To establish policies for the Compliance Engine, use the following procedure: (1) click "Add" from the top tool bar, and (2) click "Compliance Policy". On Rules tab, (3) select to match "All" or "Any" of the entered Rules, (4) in first drop-down box, select applicable rule to be set, and (5) click "Next". (6) On Actions tab, select appropriate action to take (Administrator is able to set escalation of Actions based on internal risk level decision). (7) Click "Next". (8) On Assignment tab, select device types, users, or groups to assign Policy to, and (9) click "Next". (10) View Summary for accuracy, and (11) click "Save and Assign".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50123r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47357'
  tag rid: 'SV-60229r1_rule'
  tag stig_id: 'ARWA-01-000247'
  tag gtitle: 'SRG-APP-262-MDM-181-MDIS'
  tag fix_id: 'F-51063r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001297']
  tag nist: ['SI-7']
end
