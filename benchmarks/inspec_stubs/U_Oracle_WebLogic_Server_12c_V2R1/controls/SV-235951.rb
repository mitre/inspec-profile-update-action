control 'SV-235951' do
  title 'Oracle WebLogic must provide a real-time alert when organization-defined audit failure events occur.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Notification of the failure event will allow administrators to take actions so that logs are not lost.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Diagnostics' -> 'Diagnostic Modules' 
3. Select 'Module-HealthState' from 'Diagnostic System Modules' list
4. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Watches' tab from the bottom of page
5. Ensure 'ServerHealthWatch' row has 'Enabled' column value set to 'true'
6. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Notifications' tab from the bottom of page
7. Ensure 'ServerHealthNotification' row has 'Enable Notification' column value set to 'true'

If 'ServerHealthNotification' row has 'Enable Notification' column value is not set to 'true', this is a finding."
  desc 'fix', "1. Access AC
2. Utilize 'Change Center' to create a new change session
3. From 'Domain Structure', select 'Diagnostics' -> 'Diagnostic Modules' 
4. If 'Module-HealthState' does not exist, click 'New' button. Enter 'Module-HealthState' in 'Name' field and click 'OK' button.
5. Select 'Module-HealthState' from 'Diagnostic System Modules' list
6. Select 'Configuration' tab -> 'Watches and Notifications' tab. Select the 'Watches' tab from the bottom of page
7. Click 'New' button. Set the following values in the fields as shown:
'Watch Name' = 'ServerHealthWatch' 
'Watch Type' = 'Collected Metrics'
'Enable Watch' = selected
8. Click 'Next' 
9. Click 'Add Expressions'
10. Set 'MBean Server location' dropdown value to 'ServerRuntime'. Click 'Next'
11. Set 'MBean Type' dropdown value to 'weblogic.management.runtime.ServerRuntimeMBean'. Click 'Next'
12. Set 'Instance' dropdown value to a WebLogic Server instance to be monitored. Click 'Next'
13. Select 'Enter an Attribute Expression' radio button, enter following value in 'Attribute Expression' field: HealthState.State
14. Set 'Operator' dropdown value to '>='. Set 'Value' field to '3'. Click 'Finish'
15. Repeat steps 9-14 for all WebLogic Server instances to be monitored. Click 'Finish'
16. Continuing from step 6 above, select the 'Notifications' tab from the bottom of page
17. Click 'New' button. Set 'Type' dropdown value to 'SMTP (E-Mail)'. Click 'Next'. Set the following values in the fields as shown:
'Notification Name' = 'ServerHealthNotification'
'Enable Notification' = selected
18. Click 'Next' 
19. Select an existing 'Mail Session Name', or click 'Create a New Mail Session' button to create one (JNDI name and Java mail settings must be known)
20. In 'E-Mail Recipients' text area, add list of administrator email addresses, and customize 'E-Mail Subject' and 'E-Mail Body' fields as needed. Click 'Finish'
21. Return to the 'Watches' tab from the bottom of page. Select 'ServerHealthWatch' Select 'Notifications' tab
22. Use shuttle list to set 'ServerHealthNotification' into the 'Chosen' table. Click 'Save'"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39170r628629_chk'
  tag severity: 'low'
  tag gid: 'V-235951'
  tag rid: 'SV-235951r628631_rule'
  tag stig_id: 'WBLC-02-000083'
  tag gtitle: 'SRG-APP-000108-AS-000067'
  tag fix_id: 'F-39133r628630_fix'
  tag 'documentable'
  tag legacy: ['SV-70505', 'V-56251']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
