control 'SV-243445' do
  title 'A Windows PAW must only be used to manage high-value IT resources assigned to the same tier.'
  desc 'Note: Allowed exception - For sites that are constrained in the number of available workstations, an acceptable approach is to install lower-tier administrative accounts on a separate virtual machine (VM) on the PAW workstation where higher-tier administrative accounts are installed on the host OS and lower-tier administrative accounts are installed in a VM. The VM will provide acceptable isolation between administrative accounts of different tiers.

Note: Relationship between the exception in WPAW-00-000500 and WPAW-00-001000 and requirement WPAW-00-001800: WPAW-00-000500 and WPAW-00-001000 allow an exception to the requirement for sites constrained in the number of available workstations. Lower-tier, high-value admin accounts can operate in a VM if the higher-tier, high-value admin accounts operate in the VM host-OS, but WPAW-00-001800 is more appropriate for a multiple PAW VM environment.

If administrative accounts assigned to different tiers were installed on the same PAW, it would be impossible to isolate administrative accounts to specific trust zones and protect IT resources from one trust zone (tier) from threats from high-risk trust zones.'
  desc 'check', 'Verify that a site has set aside one or more PAWs for remote management of high-value IT resources assigned to a specific tier.

Review any available site documentation.

Verify that any PAW used to manage high-value IT resources of a specific tier are used exclusively for managing high-value IT resources assigned to one and only one tier.

If the site has not set aside one or more PAWs for remote management of high-value IT resources assigned to a specific tier, this is a finding.

If PAWs used for managing high-value IT resources are used for additional functions, this is a finding.'
  desc 'fix', 'Set aside one or more PAWs for remote management of high-value IT resources assigned to a specific tier. For example, using the Microsoft Tier 0-2 model, each PAW would be assigned to manage either Tier 0, Tier 1, or Tier 2 high-value IT resources.'
  impact 0.5
  ref 'DPMS Target Windows PAW'
  tag check_id: 'C-46720r722904_chk'
  tag severity: 'medium'
  tag gid: 'V-243445'
  tag rid: 'SV-243445r722906_rule'
  tag stig_id: 'WPAW-00-000500'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46677r722905_fix'
  tag 'documentable'
  tag legacy: ['V-78147', 'SV-92853']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
