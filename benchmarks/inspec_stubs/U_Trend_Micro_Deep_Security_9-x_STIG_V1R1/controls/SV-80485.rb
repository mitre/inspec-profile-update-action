control 'SV-80485' do
  title 'Trend Deep Security detection application must detect network services that have not been authorized or approved by the organization-defined authorization or approval processes.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore, may be unreliable or serve as malicious rogues for valid services. 

This requirement can be addressed by a host-based IDS capability or by remote scanning functionality.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure network services that have not been authorized or approved by the organization-defined authorization or approval processes are detected.

Review the Intrusion Detection policy for approved ports, protocols and services associated within a defined group or a selected computer by:

- Selecting “Computers”, on the top menu bar.
- Choose the appropriate group and within the main page and select a computer for review.
- Double click the selected computer and click “Intrusion Detection”
- Verify the following settings are enabled:
  - Configuration: is set to On
  - Intrusion Prevention Behavior is set to Prevent or Detect; review local security policy for appropriate setting.  
  - Assigned Intrusion Prevention Rules: review local security policy for appropriate setting

If the Assigned Intrusion Prevention Rules do not match the local defined policy, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to detect network services that have not been authorized or approved by the organization-defined authorization or approval processes.

To configure Deep Security to detect unauthorized services through the Intrusion Detection module, go to Policies >> Intrusion Prevention>> Select New >> New intrusion Prevention Rule

- Under Details >> Application type>> Select “New”
- Enter Name of the network services
- Choose the appropriate direction 
- Select the appropriate protocol
- Choose the applicable ports'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66643r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65995'
  tag rid: 'SV-80485r1_rule'
  tag stig_id: 'TMDS-00-000330'
  tag gtitle: 'SRG-APP-000463'
  tag fix_id: 'F-72071r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002683']
  tag nist: ['SI-4 (22) (a)']
end
