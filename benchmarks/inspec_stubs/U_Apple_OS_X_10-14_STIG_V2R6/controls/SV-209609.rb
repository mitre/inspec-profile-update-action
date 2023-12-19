control 'SV-209609' do
  title 'The macOS system must prohibit user installation of software without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Operating system functionality will vary, and while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages, such as from an approved software repository.

The operating system or software configuration management utility must enforce control of software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.'
  desc 'check', 'To check if the system is configured to prohibit user installation of software, first check to ensure the Parental Controls are enabled with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 6 familyControlsEnabled | grep “/Users"

If the result is null, or does not contain “/Users/“, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9860r282309_chk'
  tag severity: 'medium'
  tag gid: 'V-209609'
  tag rid: 'SV-209609r610285_rule'
  tag stig_id: 'AOSX-14-002067'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-9860r282310_fix'
  tag 'documentable'
  tag legacy: ['SV-104723', 'V-95537']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
