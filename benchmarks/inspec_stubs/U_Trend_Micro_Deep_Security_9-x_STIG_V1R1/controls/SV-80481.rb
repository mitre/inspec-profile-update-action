control 'SV-80481' do
  title 'Trend Deep Security must implement organization-defined security safeguards to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure organization-defined security safeguards are implemented to protect its memory from unauthorized code execution.

Policies are templates that specify the settings and security rules to be configured and enforced automatically for one or more computers. These compact, manageable rule sets make it simple to provide comprehensive security without the need to manage thousands of rules. Default Policies provide the necessary rules for a wide range of common computer configurations.
Select “Computers” from the top menu and double click on any computer from the “Computers” window.
Click the “Firewall” option and review the Configuration setting under the “General” tab. 

If this is set to “Off”, this is a finding. 

Click the “Intrusion Prevention” option and review the Configuration setting under the “General” tab. 

If this is set to “Off”, this is a finding'
  desc 'fix', %q(Configure the Trend Deep Security server to implement organization-defined security safeguards to protect its memory from unauthorized code execution.

1. Create a new Policy based on a Recommendation Scan of a computer:

- On the “Computers" page, Right-click the computer, and select Actions >> Scan for Recommendations.
- When the scan is complete, return to the “Policies” page and click “New” to display the “New Policy” wizard. Enter the policy name and choose “None” from the “Inherit From” option.
- When prompted, choose to base the new Policy on "an existing computer's current configuration".
- Select "Recommended Application Types and Intrusion Prevention Rules", "Recommended Integrity Monitoring Rules", and "Recommended Log Inspection Rules" from among the computer's properties.

2. Create a new Firewall policy based on a Recommendation Scan of a computer:
 
- On the “Computers” page, Double-Click on a computer, and select Firewall >> Scan for Open Ports.
- Assign the necessary Firewall rules based on the open ports identified. Repeat for all rules as necessary.)
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66639r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65991'
  tag rid: 'SV-80481r1_rule'
  tag stig_id: 'TMDS-00-000320'
  tag gtitle: 'SRG-APP-000450'
  tag fix_id: 'F-72067r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
