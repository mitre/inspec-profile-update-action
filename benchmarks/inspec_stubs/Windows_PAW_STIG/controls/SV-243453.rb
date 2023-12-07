control 'SV-243453' do
  title 'The domain must be configured to restrict privileged administrator accounts from logging on to lower-tier hosts.'
  desc 'If the domain is not configured to restrict privileged administrator accounts from logging on to lower-tier hosts, it would be impossible to isolate administrative accounts to specific trust zones and protect IT resources from threats from high-risk trust zones. Blocking logon to lower-tier assets helps protect IT resources in a tier from being attacked from a lower tier.'
  desc 'check', 'Verify domain systems are configured to prevent higher-tier administrative accounts from logging on to lower-tier hosts.

This can be accomplished by adding the higher-tier administrative groups to the Deny log on user rights of the lower-tier system. These include the following user rights:

Deny log on as a batch job
Deny log on as a service
Deny log on locally

If domain systems are not configured to prevent higher-tier administrative accounts from logging on to lower-tier hosts, this is a finding.

Domain and Enterprise Admins are currently required to be included in the appropriate deny user rights in the Windows STIGs for member servers and workstations.

Note: Severity category exception - Upgrade to a CAT I finding if any Tier 0 administrative account used to manage high-value IT resources is able to log on to a lower-tier host.'
  desc 'fix', 'Configure domain systems to prevent higher-tier administrative accounts from logging on to lower-tier hosts.

Assign higher-tier administrative groups to the Deny log on user rights of lower-tier hosts. This includes the following user rights:

Deny log on as a batch job
Deny log on as a service
Deny log on locally

Domain and Enterprise Admins are currently required to be included in the appropriate deny user rights in the Windows STIGs for member servers and workstations.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46728r722928_chk'
  tag severity: 'medium'
  tag gid: 'V-243453'
  tag rid: 'SV-243453r722930_rule'
  tag stig_id: 'WPAW-00-001200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46685r722929_fix'
  tag 'documentable'
  tag legacy: ['V-78167', 'SV-92873']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
