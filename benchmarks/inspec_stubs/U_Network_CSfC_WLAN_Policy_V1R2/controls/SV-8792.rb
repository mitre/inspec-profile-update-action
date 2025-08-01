control 'SV-8792' do
  title 'Wireless devices connecting directly or indirectly to the network must be included in the site security plan.'
  desc 'The DAA and site commander must be aware of all approved wireless devices used at the site or DoD data could be exposed to unauthorized people.  Documentation of the enclave configuration must include all attached systems.  If the current configuration cannot be determined, then it is difficult to apply security policies effectively.  Security is particularly important for wireless technologies attached to the enclave network because these systems increase the potential for eavesdropping and other unauthorized access to network resources.'
  desc 'check', 'Review the site security plan. 
1. Wireless network devices, such as access points, laptops, CMDs, and wireless peripherals (keyboards, pointers, etc.) using a wireless network protocol, such as Bluetooth, 802.11, or proprietary protocols must be documented in the site security plan. 
2. A general statement in the site security plan permitting the various types of wireless network devices used by the site is acceptable rather than a by-model listing, for example, “wireless devices of various models are permitted as long as they are configured in accordance with the Wireless STIG”.

Mark as a finding if a DAA-approved site security plan does not exist or if it has not been updated.'
  desc 'fix', "Ensure devices connecting directly or indirectly (data synchronization) to the network are added to the site's site security plan.

(For example, it may say wireless devices of various models are permitted but only when configured in accordance with the Wireless STIG or other such specified restriction.)"
  impact 0.3
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-7611r4_chk'
  tag severity: 'low'
  tag gid: 'V-8297'
  tag rid: 'SV-8792r5_rule'
  tag stig_id: 'WIR0020'
  tag gtitle: 'Site security plan includes wireless system/equipment'
  tag fix_id: 'F-3425r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Designated Approving Authority']
  tag ia_controls: 'EBCR-1'
end
