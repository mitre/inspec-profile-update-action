control 'SV-204822' do
  title 'The application server must remove organization-defined software components after updated versions have been installed.'
  desc 'Installation of patches and updates is performed when there are errors or security vulnerabilities in the current release of the software.  When previous versions of software components are not removed from the application server after updates have been installed, an attacker may use the older components to exploit the system.'
  desc 'check', 'Review the application server documentation and configuration to determine if organization-defined software components are removed after updated versions have been installed.

If organization-defined software components are not removed after updated versions have been installed, this is a finding.'
  desc 'fix', 'Configure the application server to remove organization-defined software components after updated versions have been installed.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4942r283107_chk'
  tag severity: 'medium'
  tag gid: 'V-204822'
  tag rid: 'SV-204822r879825_rule'
  tag stig_id: 'SRG-APP-000454-AS-000268'
  tag gtitle: 'SRG-APP-000454'
  tag fix_id: 'F-4942r283108_fix'
  tag 'documentable'
  tag legacy: ['SV-71839', 'V-57563']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
