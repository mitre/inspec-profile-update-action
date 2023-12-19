control 'SV-92885' do
  title 'If several Windows PAWs are set up in virtual machines (VMs) on a host server, the host server must only contain PAW VMs.'
  desc 'A main security architectural construct of a PAW is to remove non-administrative functions from the PAW. Many standard user functions, including email processing, Internet browsing, and using business applications, can increase the security risk of the workstation. These apps and functions are susceptible to many security vulnerabilities, including phishing attacks and embedded malware. This increased risk is not acceptable for the highly privileged activities of a PAW. This requirement enforces this security concept in an environment where multiple PAW VMs are installed on a host server.

Note: Relationship between the exception in WPAW-00-000500 and WPAW-00-001000 and requirement WPAW-00-001800: WPAW-00-000500 and WPAW-00-001000 allow an exception to the requirement for sites constrained in the number of available workstations. Lower-tier, high-value admin accounts can operate in a VM if the higher-tier, high-value admin accounts operate in the VM host-OS, but WPAW-00-001800 is more appropriate for a multiple PAW VM environment.'
  desc 'check', 'Review the configuration of all host servers where PAW VMs are installed.

Verify the only VMs installed on the host server are PAW VMs.

If a host server where PAW VMs are installed contains non-PAW VMs, this is a finding.'
  desc 'fix', 'Install only PAW VMs on a host server designated for PAWs.'
  impact 0.5
  ref 'DPMS Target Privileged Access Workstation (Windows)'
  tag check_id: 'C-77745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78179'
  tag rid: 'SV-92885r1_rule'
  tag stig_id: 'WPAW-00-001800'
  tag gtitle: 'PAW-00-001800'
  tag fix_id: 'F-84901r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
