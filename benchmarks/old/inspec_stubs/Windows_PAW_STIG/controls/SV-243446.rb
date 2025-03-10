control 'SV-243446' do
  title 'All high-value IT resources must be assigned to a specific administrative tier to separate highly sensitive resources from less sensitive resources.'
  desc 'Note: The Microsoft Tier 0-2 AD administrative tier model (https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material#ADATM_BM) is an example.

A key security construct of a PAW is to separate high-value IT resources into specific trust levels so that if a device at one trust level is compromised the risk of compromise of more critical IT resources at a different tier is reduced. This architecture protects IT resources in a tier from threats from higher-risk tiers. Isolating administrative accounts by forcing them to operate only within their assigned trust zone implements the concept of containment of security risks and adversaries within a specific zone.'
  desc 'check', "Verify the site has assigned each high-value IT resource to an administrative tier level by reviewing the site's list of high-value IT resources.

In Active Directory verify each high-value IT resource has been assigned to the Organizational Unit (OU) corresponding to the administrative tier the resource is assigned to.

If the site has not assigned an administrative tier level to each high-value IT resource or any high-value IT resource is not assigned to the appropriate OU in Active Directory, this is a finding."
  desc 'fix', 'Set up an administrative tier model for the domain (for example, the Microsoft-recommended Tier 0-2 AD administrative tier model). (Details of the Tier model are found at https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material#ADATM_BM.)

Using the list of site designated high-value IT resources (see check WPAW-00-000200), indicate on the list the administrative Tier level the resource is assigned to. (Note: The updated list will be used in check WPAW-00-000400.)

In Active Directory, assign all high-value IT resources to the appropriate Organizational Units (for example):

- Admin\\Tier 0\\Devices
- Admin\\Tier 1\\Devices
- Admin\\Tier 2\\Devices'
  impact 0.5
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46721r722907_chk'
  tag severity: 'medium'
  tag gid: 'V-243446'
  tag rid: 'SV-243446r722909_rule'
  tag stig_id: 'WPAW-00-000600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46678r722908_fix'
  tag 'documentable'
  tag legacy: ['V-78149', 'SV-92855']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
