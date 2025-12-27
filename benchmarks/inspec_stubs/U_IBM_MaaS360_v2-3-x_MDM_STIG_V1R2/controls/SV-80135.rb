control 'SV-80135' do
  title 'The MaaS360 Agent must be configured to alert via the trusted channel to the MaaS360 Server for the following event: change in enrollment status.'
  desc 'Alerts providing notification of a change in enrollment state facilitate verification of the correct operation of security functions.  When a MaaS360 Server receives such an alert from a MaaS360 Agent, it indicates that the security policy may no longer be enforced on the mobile device.   This enables the MDM administrator to take an appropriate remedial action.

SFR ID: FAU_ALT_EXT.2.1'
  desc 'check', 'Review the MaaS360 server configuration to verify the MaaS360 agent alerts the MDM via the trusted channel to the MaaS360 Server for the following event: change in enrollment status.

On the MaaS360 Console complete the following Steps:
1. Navigate to Security >> Compliance Rules
2. Have system administrator identify applicable "Change in enrollment status" rule set name
3. Select  rule set name in list
4. Under Enforcement Rules, verify the "Enrollment" box is checked,  "Trigger Action on Managed Status" (all boxes need to be checked), and "Enforcement Action" is set to "alert".
5. Navigate back to Security >> Compliance Rules and verify that rule set name has been designated as default (confirm check mark) and has "1" as precedence. 

If there is no "Change in enrollment status" rule set name setup or rules that have been setup are not configured correctly, this is a finding.'
  desc 'fix', 'Configure the MaaS360 Agent to alert via the trusted channel to the MaaS360 Server for the following event: change in enrollment status

On the MaaS360 Console complete the following Steps:
1. Navigate to Security >> Compliance Rules >> Add Rule Set and Create a rule
2. Under Basic Settings >> Select Applicable Platforms select the MOS and under "Event Notification Recipients" input the email for the non-compliant devices/users
3. Under Enforcement Rules >> Select Enforcement Rules ensure the "Enrollment" box is checked and the following boxes are checked:

"Trigger Action on Managed Status"  all boxes need to be checked, ensure "Enforcement Action" is set to "alert"'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 v2.3.x MDM'
  tag check_id: 'C-66205r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65645'
  tag rid: 'SV-80135r1_rule'
  tag stig_id: 'M360-01-020400'
  tag gtitle: 'PP-MDM-202003'
  tag fix_id: 'F-71573r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
