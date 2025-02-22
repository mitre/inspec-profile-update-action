control 'SV-82795' do
  title 'The Mainframe product must prohibit user installation of software without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages, such as from an approved software repository. 

The application must enforce software installation by users based on what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization. 

This requirement applies, for example, to applications that provide the ability to extend application functionality (e.g., plug-ins, add-ons) and software management applications.'
  desc 'check', 'Examine installation and configuration settings for change management.

If the Mainframe Product does not identify installation privilege roles and prohibit user installation of software without explicit privileged status, this is a finding.

If the Mainframe Product uses an external security manager (ESM) and there are no rules for the identified roles and access is not restricted to appropriate privileged users according to site security plan, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to prohibit user installation of software without explicit privileged status.

If the Mainframe Product uses an ESM, configure the ESM to include rules for installation of software-privileged roles.

Configure the roles to restrict access for software installation to the user with privilege status.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68305'
  tag rid: 'SV-82795r1_rule'
  tag stig_id: 'SRG-APP-000378-MFP-000185'
  tag gtitle: 'SRG-APP-000378-MFP-000185'
  tag fix_id: 'F-74419r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
