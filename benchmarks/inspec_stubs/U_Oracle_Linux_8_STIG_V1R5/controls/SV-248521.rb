control 'SV-248521' do
  title 'OL 8 must be a vendor-supported release.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements. 
 
Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify the version of the operating system is vendor supported. 
 
Check the version of the operating system with the following command: 
 
$ udo cat /etc/oracle-release 
 
Oracle Linux Server release 8.2 
 
Current End of Premier Support for Oracle Linux 8 is July 2029, while Extended Support might consider an extended term. 
 
If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51955r779127_chk'
  tag severity: 'high'
  tag gid: 'V-248521'
  tag rid: 'SV-248521r779129_rule'
  tag stig_id: 'OL08-00-010000'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51909r779128_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
