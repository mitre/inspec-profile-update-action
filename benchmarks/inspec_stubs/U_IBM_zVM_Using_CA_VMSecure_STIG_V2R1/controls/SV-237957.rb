control 'SV-237957' do
  title 'CA VM:Secure product VMXRPI configuration file must be restricted to authorized personnel.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.

The VMXRPI CONFIG file contains records that determine the activity that can occur when the Rules Facility is not available, and provides the configuration information for the Rules Facility.'
  desc 'check', 'Query the CA VM:Secure rules.

If there are product rules granting access to the disk on which the “VMXRPI” configuration file resides for system administrators only, this is not a finding.'
  desc 'fix', 'Create rules in the CA VM:Secure product Rules Facility that restricts access to the disk where the “VMXRPI” configuration file resides to system administrators only.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41167r649709_chk'
  tag severity: 'medium'
  tag gid: 'V-237957'
  tag rid: 'SV-237957r649711_rule'
  tag stig_id: 'IBMZ-VM-001220'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-41126r649710_fix'
  tag 'documentable'
  tag legacy: ['SV-93667', 'V-78961']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
