control 'SV-233184' do
  title 'The container platform must prohibit the installation of patches and updates without explicit privileged status.'
  desc 'Controlling access to those users and roles responsible for patching and updating the container platform reduces the risk of untested or potentially malicious software from being installed within the platform. This access may be separate from the access required to install container images into the registry and those access requirements required to instantiate an image into a service. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.'
  desc 'check', 'Review the container platform configuration to determine if patches and updates can only be installed through accounts with privileged status. 

Attempt to install a patch or upgrade using a non-privileged user account. 

If patches or updates can be installed using a non-privileged account or the container platform is not configured to stop the installation using a non-privileged account, this is a finding.'
  desc 'fix', 'Configure the container platform to only allow patch installation and upgrades using privileged accounts.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36120r601789_chk'
  tag severity: 'medium'
  tag gid: 'V-233184'
  tag rid: 'SV-233184r601790_rule'
  tag stig_id: 'SRG-APP-000378-CTR-000880'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-36088r601040_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
