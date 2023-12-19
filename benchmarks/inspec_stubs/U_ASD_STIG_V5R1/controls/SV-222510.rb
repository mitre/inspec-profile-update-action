control 'SV-222510' do
  title 'The application must prohibit user installation of software without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository.

The application must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.

This requirement applies, for example, to applications that provide the ability to extend application functionality (e.g., plug-ins, add-ons) and software management applications.'
  desc 'check', 'Review the application documentation and interview the application administrator to determine the capabilities of the application as it relates to software installation or product function extension.

Identify any software configuration change capabilities which are allowed by design and incorporated into the user interface. An example is utilizing a known software repository of tested and approved extensions, plugins or modules which can be used by application users to extend application features or functions.

If the application does not provide the ability to install software components, modules, plugins, or extensions, the requirement is not applicable.

Access the application user interface as a regular user, navigate to the application screen that provides the software installation function and attempt to install software components, modules, extensions, or plugins.

If the application utilizes an approved repository of approved software that has been tested and approved for all application users to install, this is not a finding.

If the application allows regular users to install untested or unapproved software components, extensions, modules, or plugins without explicit authorization, this is a finding.'
  desc 'fix', 'Configure the application to prohibit user installation of software without explicit permission.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24180r493438_chk'
  tag severity: 'medium'
  tag gid: 'V-222510'
  tag rid: 'SV-222510r508029_rule'
  tag stig_id: 'APSC-DV-001390'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-24169r493439_fix'
  tag 'documentable'
  tag legacy: ['SV-84125', 'V-69503']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
