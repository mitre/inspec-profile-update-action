control 'SV-215632' do
  title 'The Windows 2012 DNS Server must restrict individuals from using it for launching Denial of Service (DoS) attacks against other information systems.'
  desc 'Applications and application developers must take the steps needed to ensure users cannot use an authorized application to launch DoS attacks against other systems and networks. For example, applications may include mechanisms that throttle network traffic so users are not able to generate unlimited network traffic via the application. Limiting system resources that are allocated to any user to a bare minimum may also reduce the ability of users to launch some DoS attacks.'
  desc 'check', 'Review the DNS server to confirm the server restricts direct and remote console access to users other than Administrators.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on through Remote Desktop Services" user right, this is a finding: 

Administrators

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny access to this computer from the network" user right, this is a finding: 

Guests Group

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on locally" user right, this is a finding: 

Guests Group'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on through Remote Desktop Services" to only include the following accounts or groups:

Administrators

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny access to this computer from the network" to include the following:

Guests Group

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on locally" to include the following:

Guests Group'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16826r314371_chk'
  tag severity: 'medium'
  tag gid: 'V-215632'
  tag rid: 'SV-215632r561297_rule'
  tag stig_id: 'WDNS-SC-000026'
  tag gtitle: 'SRG-APP-000246-DNS-000035'
  tag fix_id: 'F-16824r314372_fix'
  tag 'documentable'
  tag legacy: ['SV-73127', 'V-58697']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
