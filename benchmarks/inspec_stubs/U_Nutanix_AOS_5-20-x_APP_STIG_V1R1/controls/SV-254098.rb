control 'SV-254098' do
  title 'Nutanix AOS must disable Remote Support Sessions.'
  desc 'Application servers provide remote access capability and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements. Automated monitoring and control of remote access sessions allows organizations to detect cyberattacks and also ensure ongoing compliance with remote access policies by logging connection activities of remote users.

Examples of policy requirements include, but are not limited to, authorizing remote access to the information system, limiting access based on authentication credentials, and monitoring for unauthorized access.'
  desc 'check', 'Confirm Nutanix AOS Prism Elements is configured to manage remote access.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the Remote Support section to verify the ability to disable remote sessions, and that it is checked.

If Disable Remote Sessions is not available, or is not checked, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS Prism Elements to disable Remote Sessions. If the ability to disable Remote Sessions is not available there is corruption within the CVM. A rebuild is necessary to clear out the corruption and get the CVM back to a positive state.

Rebuild the CVM by booting from ISO.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57583r846380_chk'
  tag severity: 'medium'
  tag gid: 'V-254098'
  tag rid: 'SV-254098r846382_rule'
  tag stig_id: 'NUTX-AP-000020'
  tag gtitle: 'SRG-APP-000315-AS-000094'
  tag fix_id: 'F-57534r846381_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
