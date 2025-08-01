control 'SV-96909' do
  title 'The MaaS360 MDM Agent must provide an alert via the trusted channel to the MDM server for the following event: change in enrollment state.'
  desc 'Alerts providing notification of a change in enrollment state facilitate verification of the correct operation of security functions. When an MDM server receives such an alert from a MaaS360 MDM Agent, it indicates that the security policy may no longer be enforced on the mobile device. This enables the MDM administrator to take an appropriate remedial action.

SFR ID: FAU_ALT_EXT.2.1'
  desc 'check', 'Review the MaaS360 server configuration to verify the MaaS360 Agent alerts the MDM via the trusted channel to the MaaS360 server for the following event: change in enrollment status.

On the MaaS360 Console, complete the following steps:
1. Navigate to Security >> Compliance Rules.
2. Have the system administrator identify the applicable "Change in enrollment status" rule set name.
3. Select rule set name in list.
4. Under “Enforcement Rules”, verify the "Enrollment" box is checked, all boxes are checked for "Trigger Action on Managed Status", and "Enforcement Action" is set to "alert".

If there are no "Change in enrollment status" rule set names set up or rules that have been set up are not configured correctly, this is a finding.'
  desc 'fix', 'Configure the MaaS360 Agent to alert via the trusted channel to the MaaS360 server for the following event: change in enrollment status

On the MaaS360 Console, complete the following steps:
1. Navigate to Security >> Compliance Rules >> Add Rule Set and Create a rule.
2. Under Basic Settings >> Select Applicable Platforms, select the MOS, and under "Event Notification Recipients", input the email for the system administrator who will get the notification.
3. Under “Enforcement Rules”, select Enforcement Rules and ensure the "Enrollment" box is checked and that all boxes for "Trigger Action on Managed Status" are checked.
4. Ensure "Enforcement Action" is set to "alert".'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81997r1_chk'
  tag severity: 'medium'
  tag gid: 'V-82195'
  tag rid: 'SV-96909r1_rule'
  tag stig_id: 'M360-10-300100'
  tag gtitle: 'PP-MDM-302001'
  tag fix_id: 'F-89055r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
