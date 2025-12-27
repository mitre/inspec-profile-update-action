control 'SV-46354' do
  title 'The production web-site must configure the Global .NET Trust Level.'
  desc "An application's trust level determines the permissions granted by the ASP.NET Code Access Security (CAS) policy.  An application with full trust permissions may access all resource types on a server and perform privileged operations, while applications running with partial trust have varying levels of operating permissions and access to resources. The CAS determines the permissions granted to the application on the server. Setting a level of trust compatible with the applications will limit the potential harm a compromised application could cause to a system."
  desc 'check', 'Note: If the server being reviewed is a non-production website, this is Not Applicable.
Note: Setting a web application Trust Level to MEDIUM may deny some application permissions. If compatibility issues with applications require trust level to be less than "Medium", this check can be downgraded to a Cat III with supporting documentation from the Authorizing Official (AO).

1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click the ".NET Trust Level" icon.
4. If the .NET Trust level is not set to "Medium" or less, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Double-click the ".NET Trust Level" icon.
4. Set the .NET Trust level to "Medium" or less and click "Apply".'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32886r7_chk'
  tag severity: 'medium'
  tag gid: 'V-26034'
  tag rid: 'SV-46354r3_rule'
  tag stig_id: 'WA000-WI6200'
  tag gtitle: 'WA000-WI6200'
  tag fix_id: 'F-29034r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
