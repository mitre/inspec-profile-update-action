control 'SV-95131' do
  title 'The Bromium Enterprise Controller (BEC) must be configured for authorized system administrators to capture and log content related to a Bromium vSentry client.'
  desc 'Without the capability to capture and log all content related to a user session, investigations into suspicious user activity would be hampered.

By default, untrusted file, web, and application activity is captured for each user on the BEC. Additional custom rules can be created within the "Policy" section of the BEC. The security administrator can determine if additional rules are needed based on organization-based requirements and the mission.

The Bromium monitoring module includes a base monitoring policy that detects malicious file, registry, process, and network activity. The monitoring module also features the ability to create custom rules to monitor user activity, such as:

1. Read operations on files and registry settings;
2. Write operations on files and registry settings;
3. Read/write operations on files and registry settings; and
4. Processes being launched.'
  desc 'check', %q(If custom rules are required, verify that monitoring rules are enabled. Custom rules may or may not be present on the BEC, depending on the site's need. It is not mandatory to use this feature, just that the feature be configured to be used in case it is needed.

1. From the management console, click on "Policies".
2. Select the base policy that covers all devices.
3. Within the base policy, select the "Features" tab, navigate to the "Monitoring" section, and verify that "Host Monitoring" is enabled.
4. Click on "Policies" and verify "Monitoring Rules" is checked.

If the Bromium Enterprise Controller (BEC) is not configured for authorized users to capture and log content related to a user session, this is a finding.)
  desc 'fix', %q(Configure a custom rule to view a user's activity.

Ensure host monitoring is enabled in the base or applicable delta policy.

1. From the management console, click on "Policies".
2. Select the base policy that covers all devices.
3. Within the base policy, select the "Features" tab, navigate to the "Monitoring" section, and enable "Host Monitoring".
4. Click "Save and Deploy". 

Configure the Custom Rule to monitor one or more Bromium vSentry clients.
1. Click the arrow next to "Policies" and select "Monitoring Rules".
2. Click "Rule Options" and select "Create Custom Rule".
3. Create a name for the custom rule.
4. Apply the custom rule to a group.
5. Configure the applications, triggers, and any exclusions associated with the activity to be monitored.
6. Click "Save".)
  impact 0.3
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80099r1_chk'
  tag severity: 'low'
  tag gid: 'V-80427'
  tag rid: 'SV-95131r1_rule'
  tag stig_id: 'BROM-00-000155'
  tag gtitle: 'SRG-APP-000093'
  tag fix_id: 'F-87233r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end
