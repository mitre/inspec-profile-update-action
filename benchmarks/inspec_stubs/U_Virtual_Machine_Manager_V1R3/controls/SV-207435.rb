control 'SV-207435' do
  title 'The VMM must control remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and VMMs, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic VMMs by an authorized user (or another VMM) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 

VMM functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of VMM components (e.g., servers, workstations, notebook computers, smart phones, and tablets).'
  desc 'check', 'Verify the VMM controls remote access methods.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to control remote access methods.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7692r365715_chk'
  tag severity: 'medium'
  tag gid: 'V-207435'
  tag rid: 'SV-207435r854610_rule'
  tag stig_id: 'SRG-OS-000297-VMM-001040'
  tag gtitle: 'SRG-OS-000297'
  tag fix_id: 'F-7692r365716_fix'
  tag 'documentable'
  tag legacy: ['V-57071', 'SV-71331']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
