control 'SV-207202' do
  title 'The VPN Gateway log must protect audit information from unauthorized modification when stored locally.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

This requirement pertains to securing the VPN log as it is stored locally, on the box temporarily, or while being encapsulated.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations.

Audit information includes all information (e.g., log records, audit settings, and audit reports) needed to successfully audit information system activity.

This requirement only applies to components where this is specific to the function of the device (e.g., IDPS sensor logs, firewall logs). This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the VPN Gateway log is configured to protect audit information from unauthorized modification when stored locally.

The VPN Gateway log must protect audit information from unauthorized modification when stored locally, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway log to protect audit information from unauthorized modification when stored locally. The method used depends on system architecture and design. Examples: ensuring log files receive the proper file system permissions and limiting log data locations.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7462r378227_chk'
  tag severity: 'medium'
  tag gid: 'V-207202'
  tag rid: 'SV-207202r608988_rule'
  tag stig_id: 'SRG-NET-000099-VPN-000380'
  tag gtitle: 'SRG-NET-000099'
  tag fix_id: 'F-7462r378228_fix'
  tag 'documentable'
  tag legacy: ['SV-106213', 'V-97075']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
