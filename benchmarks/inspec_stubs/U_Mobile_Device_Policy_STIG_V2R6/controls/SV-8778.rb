control 'SV-8778' do
  title 'All wireless/mobile systems (including associated peripheral devices, operating system, applications, network/PC connection methods, and services) must be approved by the approval authority prior to installation and use for processing DoD information.'
  desc 'Unauthorized wireless systems expose DoD networks to attack. The Authorizing Official (AO) and appropriate commanders must be aware of all wireless systems used at the site. AOs should ensure a risk assessment for each system, including associated services and peripherals, is conducted before approving. Accept risks only when needed to meet mission requirements.'
  desc 'check', '1. Request copies of written AO approval documentation for wireless/mobile devices used by the site. 

2. Verify AO approval for wireless/mobile devices in use at the site. 

Note: The AO approval for wireless/mobile systems does not need to be documented separately from other AO approval documents for the site network, as long as the approval documents list the wireless/mobile systems in use at the site. For example, if a site network ATO lists the wireless system, the ATO meets the requirements of this check.

If the AO has not approved all wireless/mobile devices used at the site, this is a finding.'
  desc 'fix', 'Obtain AO approval prior to wireless systems being installed and used.'
  impact 0.7
  ref 'DPMS Target Mobile Device Policy'
  tag check_id: 'C-3890r8_chk'
  tag severity: 'high'
  tag gid: 'V-8283'
  tag rid: 'SV-8778r7_rule'
  tag stig_id: 'WIR0005'
  tag gtitle: 'Wireless/mobile systems authorized prior to use'
  tag fix_id: 'F-19194r4_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Designated Approving Authority', 'Information Assurance Manager']
end
