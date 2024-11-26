control 'WDNS-22-000067_rule' do
  title 'The Windows 2022 DNS Server must restrict individuals from using it for launching denial-of-service (DoS) attacks against other information systems.'
  desc 'Applications and application developers must take steps to ensure users cannot use an authorized application to launch DoS attacks against other systems and networks. For example, applications may include mechanisms that throttle network traffic, so users are not able to generate unlimited network traffic via the application. Limiting system resources that are allocated to any user to a bare minimum may also reduce the ability of users to launch some DoS attacks.'
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
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Allow log on through Remote Desktop Services to include only the following accounts or groups:

Administrators

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Deny access to this computer from the network to include the following:

Guests Group

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Deny log on locally to include the following:

Guests Group'
  impact 0.5
  tag check_id: 'C-WDNS-22-000067_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000067'
  tag rid: 'WDNS-22-000067_rule'
  tag stig_id: 'WDNS-22-000067'
  tag gtitle: 'SRG-APP-000246-DNS-000035'
  tag fix_id: 'F-WDNS-22-000067_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
