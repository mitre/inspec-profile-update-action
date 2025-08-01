control 'SV-80479' do
  title 'Trend Deep Security must protect against or limit the effects of all types of Denial of Service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of applications to mitigate the impact of DoS attacks that have occurred or are ongoing on application availability. For each application, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the effects of all types of Denial of Service (DoS) attacks are protected against or limited by employing organization-defined security safeguards.

Policies are templates that specify the settings and security rules to be configured and enforced automatically for one or more computers. These compact, manageable rule sets make it simple to provide comprehensive security without the need to manage thousands of rules. Default Policies provide the necessary rules for a wide range of common computer configurations. 

Select “Computers” from the top menu and double click on any computer from the “Computers” area. 
Click the “Firewall” menu and review the configuration setting under the “General” tab. 

If Firewall >> Configuration is set to "Off", this is a finding. 

Click the “Intrusion Prevention” menu and review the configuration setting under the “General” tab. 

If Intrusion Prevention >> Configuration is set to “Off”, this is a finding.'
  desc 'fix', %q(Configure the Trend Deep Security server to protect against or limit the effects of all types of Denial of Service (DoS) attacks by employing organization-defined security safeguards.

1. Create a new Policy based on a Recommendation Scan of a computer:

- On the “Computers" page, Right-click the computer, and select Actions >> Scan for Recommendations.
- When the scan is complete, return to the “Policies” page and click “New” to display the “New Policy” wizard. Enter the policy name and choose “None” from the “Inherit From” option.
- When prompted, choose to base the new Policy on "an existing computer's current configuration".
- Select "Recommended Application Types and Intrusion Prevention Rules", "Recommended Integrity Monitoring Rules", and "Recommended Log Inspection Rules" from among the computer's properties.

2. Create a new Firewall policy based on a Recommendation Scan of a computer:
 
- On the “Computers” page, Double-click on a computer, and select Firewall >> Scan for Open Ports.
- Assign the necessary Firewall rules based on the open ports identified. Repeat for all rules as necessary.)
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66637r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65989'
  tag rid: 'SV-80479r1_rule'
  tag stig_id: 'TMDS-00-000315'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-72065r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
