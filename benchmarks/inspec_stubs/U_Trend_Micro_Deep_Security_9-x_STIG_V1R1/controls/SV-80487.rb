control 'SV-80487' do
  title 'Trend Deep Security must, when unauthorized network services are detected, log the event and alert the ISSO, ISSM, and other individuals designated by the local organization.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore, may be unreliable or serve as malicious rogues for valid services. The detection of such unauthorized services must be logged and appropriate personnel must be notified. 

This requirement can be addressed by a host-based IDS capability or by remote scanning functionality.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the event is logged, and the ISSO, ISSM, and other individuals designated by the local organization are alerted when unauthorized network services are detected.

Policies are templates that specify the settings and security rules to be configured and enforced automatically for one or more computers. These compact, manageable rule sets make it simple to provide comprehensive security without the need to manage thousands of rules. Default Policies provide the necessary rules for a wide range of common computer configurations. 

Select “Computers” from the top menu and double click on any computer from the list.

Under Firewall >> General Tab >> Firewall area, verify "Configuration" is set to "On".

If "Configuration" is set to “Off”, this is a finding. 

Under Intrusion Detection >> General Tab >> Intrusion Detection area, verify "Configuration" is set to "On".

If "Configuration" is set to “Off”, this is a finding.'
  desc 'fix', %q(Configure the Trend Deep Security server to log the event and alert the ISSO, ISSM, and other individuals designated by the local organization, when unauthorized network services are detected.

Create a new Policy based on a Recommendation Scan of a computer.

To do so, right click the computer on the “Computers” page and select Actions >> Scan for Recommendations.
 
When the scan is complete, return to the “Policies” page and click “New” to display the “New Policy” wizard.

Enter the policy name and choose “None” from the “Inherit From” option.

When prompted, choose to base the new Policy on "an existing computer's current configuration".
 
Then select "Recommended Application Types and Intrusion Prevention Rules", "Recommended Integrity Monitoring Rules", and "Recommended Log Inspection Rules" from among the computer's properties.

Firewall rules should be created for each individual computer in order to prevent services from being disrupted.

You can create a new Firewall policy based on a Recommendation Scan of a computer.

To do so, double click on a computer on the Computers page and select Firewall >> Scan for Open Ports.

Assign the necessary Firewall rules based on the open ports identified.

Apply other rules as necessary.)
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66645r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65997'
  tag rid: 'SV-80487r1_rule'
  tag stig_id: 'TMDS-00-000335'
  tag gtitle: 'SRG-APP-000464'
  tag fix_id: 'F-72073r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
