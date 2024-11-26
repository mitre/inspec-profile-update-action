control 'SV-219060' do
  title 'The Mainframe Product must provide the capability for authorized users to select a user session to capture/record or view/hear.'
  desc 'Without the capability to select a user session to capture/record or view/hear, investigations into suspicious or harmful events would be hampered by the volume of information captured. The volume of information captured may also adversely impact the operation for the network.

Session audits may include monitoring keystrokes, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'If the Mainframe Product has no function or capability for session operations, this is not applicable.

Examine installation and configuration settings.

Verify that the Mainframe Product has the capability to select user sessions for monitoring and allows system programmers and security administrators to select sessions to capture/record or view/hear in accordance with applicable access control policies. 

If it does not, this is a finding.

If there is an external security manager (ESM) in use, verify that the ESM restricts the ability to select sessions to capture/record or view/hear in accordance with applicable access control policies to system programmers or security administrators. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to permit authorized users to select a user session to capture/record or view/hear.

If there is an ESM in use, configure ESM to restrict the ability to select sessions to capture/record or view/hear in accordance with applicable access control policies to system programmers or security administrators.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5816r69548_chk'
  tag severity: 'medium'
  tag gid: 'V-219060'
  tag rid: 'SV-219060r865836_rule'
  tag stig_id: 'SRG-APP-000354-MFP-000136'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-20869r859694_fix'
  tag 'documentable'
  tag legacy: ['SV-82723', 'V-68233']
  tag cci: ['CCI-001919']
  tag nist: ['AU-14 a']
end
