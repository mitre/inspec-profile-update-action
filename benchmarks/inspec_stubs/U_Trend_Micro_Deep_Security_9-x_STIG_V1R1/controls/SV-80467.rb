control 'SV-80467' do
  title 'Trend Deep Security must prohibit user installation of software without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. 

The application must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization. 

This requirement applies, for example, to applications that provide the ability to extend application functionality (e.g., plug-ins, add-ons) and software management applications.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure user installation of software without explicit privileged status is prohibited.

Analyze the system using Administration >> User Management >> Roles.
Review each role created that is not “Full Access”.
Right-Click >> Properties on the desired role, and select “Other Rights.”
The “Updates” setting should be set to “View Only” or “Hide.” 

If any other option is selected other than “View Only” or “Hide”, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to prohibit user installation of software without explicit privileged status.

Configure the application to prevent non-authorized users from updating Deep Security by selecting Administration >> User Management >> Roles.
Right-Click >> Properties on any of the roles listed and choose “Other Rights.”
Set the “Updates” setting to “View Only” or “Hide”.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66625r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65977'
  tag rid: 'SV-80467r1_rule'
  tag stig_id: 'TMDS-00-000285'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-72053r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
