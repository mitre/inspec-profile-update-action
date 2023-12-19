control 'SV-95189' do
  title 'The Bromium Enterprise Controller (BEC) must be configured to allow authorized administrators to create organization-defined custom rules to support mission and business requirements.'
  desc 'Without the capability to create custom rules specific to the business and mission needs of the organization, detection of suspicious user activity would be hampered.

Additional custom rules can be created within the "Policy" section of the BEC. The security administrator can determine if additional rules are needed based on organization requirements and mission.

The Bromium monitoring module includes a base monitoring policy that detects malicious file, registry, process, and network activity. The monitoring module also features the ability to create custom rules to monitor such user activity as:

1. Read operations on files and registry settings;
2. Write operations on files and registry settings;
3. Read/write operations on files and registry settings; and
4. Processes being launched.'
  desc 'check', 'Ask the site representative for the System Security Policy (SSP) document that includes the security policy settings required for endpoint security and monitoring. If custom monitoring rules are required, verify that monitoring rules are enabled and that custom rules are configured within the policy and applied to the appropriate devices.

1. From the management console, click on "Policies".
2. Select the base policy that covers all devices.
3. Within the base policy, select the "Features" tab, navigate to the "Monitoring" section, and verify that "Host Monitoring" is enabled.
4. Click the arrow next to "Policies" and select "Monitoring Rules".
5. Review custom rules and the device groups they are applied to. 

If the BEC is not configured for authorized users to capture and log content related to a user session, this is a finding.

If the BEC is not configured to allow authorized administrators to create organization-defined custom rules to support mission and business requirements, this is a finding.'
  desc 'fix', 'Create an SSP document that contains requirements for implementing Bromium vSentry policy settings and workflows for the endpoint. Bromium vSentry policy settings are accessible in the "Policy" section of the BEC. Custom monitoring rules are available in the "Monitoring Rules" section under "Policy".

1. From the management console, click on "Policies".
2. Select the base policy that covers all devices.
3. Within the base policy, select the "Features" tab, navigate to the "Monitoring" section, and enable "Host Monitoring".
4. Click "Save and Deploy". 
5. Click the arrow next to "Policies" and select "Monitoring Rules".
6. Click "Rule Options" and select "Create Custom Rule".
7. Create a name for the custom rule.
8. Apply the custom rule to a group.
9. Configure the applications, triggers, and any exclusions associated with the activity to be monitored.
10. Click "Save ".'
  impact 0.3
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80157r1_chk'
  tag severity: 'low'
  tag gid: 'V-80481'
  tag rid: 'SV-95189r1_rule'
  tag stig_id: 'BROM-00-001310'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-87291r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
