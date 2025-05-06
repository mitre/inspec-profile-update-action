control 'SV-207228' do
  title 'The VPN Gateway must be configured to perform an organization-defined action if the audit reveals unauthorized activity.'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and makes remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Remote access functionality, such as remote access servers, VPN concentrators, and IDS/IPS devices, must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets).'
  desc 'check', 'Verify the VPN Gateway is configured to perform an organization-defined action if the audit reveals unauthorized activity.

If the VPN Gateway does not be configured to perform an organization-defined action if the audit reveals unauthorized activity, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to be configured to perform an organization-defined action if the audit reveals unauthorized activity.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7488r378305_chk'
  tag severity: 'medium'
  tag gid: 'V-207228'
  tag rid: 'SV-207228r856701_rule'
  tag stig_id: 'SRG-NET-000313-VPN-001050'
  tag gtitle: 'SRG-NET-000313'
  tag fix_id: 'F-7488r378306_fix'
  tag 'documentable'
  tag legacy: ['V-97135', 'SV-106273']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
