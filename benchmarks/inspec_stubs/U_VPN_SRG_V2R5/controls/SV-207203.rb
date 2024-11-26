control 'SV-207203' do
  title 'The VPN Gateway must protect audit information from unauthorized deletion when stored locally.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations.

Audit information includes all information (e.g., log records, audit settings, and audit reports) needed to successfully audit information system activity.

This requirement only applies to components where this is specific to the function of the device (e.g., IDPS sensor logs, firewall logs). This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the VPN Gateway is configured to protect audit information from unauthorized deletion when stored locally.

If the VPN Gateway does not protect audit information from unauthorized deletion when stored locally, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to protect audit information from unauthorized deletion when stored locally. Ensure log files receive the proper file system permissions and limiting log data locations.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7463r378230_chk'
  tag severity: 'medium'
  tag gid: 'V-207203'
  tag rid: 'SV-207203r608988_rule'
  tag stig_id: 'SRG-NET-000100-VPN-000390'
  tag gtitle: 'SRG-NET-000100'
  tag fix_id: 'F-7463r378231_fix'
  tag 'documentable'
  tag legacy: ['V-97077', 'SV-106215']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
