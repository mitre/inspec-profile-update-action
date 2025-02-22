control 'SV-83299' do
  title 'VMware ESX operating systems, virtual machines, and associated management software that are no longer supported by the vendor for security updates must not be installed on a system.'
  desc 'VMware ESX operating systems, virtual machines, and associated management software that are no longer supported by VMware for security updates are not evaluated or updated for vulnerabilities leaving them open to potential attack.  Organizations must transition to a supported ESXi operating system, virtual machines, and associated management software to ensure continued support.'
  desc 'check', 'VMware support for ESX versions 3 and 4 ended 21 May 2016.  If ESX version 3 or 4, virtual machines, or associated management software, such as VirtualCenter, is installed on a system, this is a finding.'
  desc 'fix', 'Upgrade ESX version 3 and 4 systems, virtual machines, and associated management software to supported versions.'
  impact 0.7
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-69213r3_chk'
  tag severity: 'high'
  tag gid: 'V-68721'
  tag rid: 'SV-83299r1_rule'
  tag stig_id: 'ESX0100'
  tag gtitle: 'VMware ESX 3 and 4 Unsupported'
  tag fix_id: 'F-74843r3_fix'
  tag 'documentable'
end
