control 'SV-243449' do
  title 'The Windows PAW must be configured so that all non-administrative-related applications and functions are blocked or removed from the PAW platform, including but not limited to email, Internet browsing, and line-of-business applications.'
  desc 'Note: The intent of this requirement is that a PAW must not be used for any function not related to the management of high-value IT resources.

Note: Authorized exception - It is noted that administrators will need access to non-administrative functions, such as email and the Internet, but a PAW must not be used for these activities. For sites that are constrained in the number of available workstations, an acceptable approach is to install the non-administrative services on a separate virtual machine (VM) on the workstation where the PAW service is installed. The VM will provide acceptable isolation between high-value administrative management accounts and non-administrative services.

Note: Relationship between the exception in WPAW-00-000500 and WPAW-00-001000 and requirement WPAW-00-001800: WPAW-00-000500 and WPAW-00-001000 allow an exception to the requirement for sites constrained in the number of available workstations. Lower-tier, high-value admin accounts can operate in a VM if the higher-tier, high-value admin accounts operate in the VM host-OS, but WPAW-00-001800 is more appropriate for a multiple PAW VM environment.

A main security architectural construct of a PAW is to remove non-administrative applications and functions from the PAW workstation. Many standard user applications and functions, including email processing, Internet browsing, and using business applications, can increase the security risk to the workstation. These apps and functions are susceptible to many security vulnerabilities, including phishing attacks and embedded malware. This increased risk is not acceptable for the highly privileged activities of a PAW.'
  desc 'check', 'Note: Internet browsing is blocked using the PAW host-based firewall or by configuring a proxy address with a loopback address on the PAW. (See STIG check WPAW-00-002200.) Blocking Internet browsing does not need to be verified in this procedure.

Review the services and applications installed on the PAW.

Verify there are no email applications/clients and line-of-business applications installed on the PAW.

If email applications/clients or line-of-business applications are installed on the PAW, this is a finding.'
  desc 'fix', 'Remove email applications and all line-of business applications from the PAW.

Note: Internet browsing is blocked using the PAW host-based firewall or by configuring a proxy address with a loopback address on the PAW. (See STIG check WPAW-00-002200.)'
  impact 0.5
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46724r722916_chk'
  tag severity: 'medium'
  tag gid: 'V-243449'
  tag rid: 'SV-243449r722918_rule'
  tag stig_id: 'WPAW-00-001000'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46681r722917_fix'
  tag 'documentable'
  tag legacy: ['V-78155', 'SV-92861']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
