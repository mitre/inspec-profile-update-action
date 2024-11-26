control 'SV-243454' do
  title 'A Windows PAW used to manage domain controllers and directory services must not be used to manage any other type of high-value IT resource.'
  desc 'Domain controllers (DC) are usually the most sensitive, high-value IT resources in a domain. Dedicating a PAW to be used solely for managing domain controllers will aid in protecting privileged domain accounts from being compromised.

For Windows, this includes the management of Active Directory itself and the DCs that run Active Directory, including such activities as domain-level user and computer management, administering trusts, replication, schema changes, site topology, domain-wide group policy, the addition of new DCs, DC software installation, and DC backup and restore operations.'
  desc 'check', 'If domain controllers and directory services are only managed with local logons to domain controllers, not remotely, this requirement is not applicable. 

Discuss with the Information System Security Manager (ISSM) or PAW system administrators and review any available site documentation.

Verify that a site has designated specific PAWs for the sole purpose of remote management of domain controllers and directory service servers.

Review any available site documentation.

Verify that any PAW used to manage domain controllers and directory services remotely are used exclusively for managing domain controllers and directory services.

If the site has not designated specific PAWs for the sole purpose of remote management of domain controllers and directory service servers, this is a finding.

If PAWs used for managing domain controllers and directory services are used for additional functions, this is a finding.'
  desc 'fix', 'Set aside one or more PAWs for remote management of Active Directory.

Ensure they are used only for the purpose of managing directory services. Otherwise, use the local domain controller console to manage Active Directory.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46729r722931_chk'
  tag severity: 'high'
  tag gid: 'V-243454'
  tag rid: 'SV-243454r722933_rule'
  tag stig_id: 'WPAW-00-001300'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-46686r722932_fix'
  tag 'documentable'
  tag legacy: ['V-78169', 'SV-92875']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
