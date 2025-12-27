control 'SV-234520' do
  title 'The UEM server must prohibit user installation of software by an administrator without the appropriate assigned permission for software installation.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. 

The application must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization. 

This requirement applies, for example, to applications that provide the ability to extend application functionality (e.g., plug-ins, add-ons) and software management applications. 

Satisfies:FPT_TUD_EXT.1.2'
  desc 'check', 'Verify the UEM server prohibits user installation of software by an administrator without the appropriate assigned permission for software installation.

If the UEM server does not prohibit user installation of software by an administrator without the appropriate assigned permission for software installation, this is a finding.'
  desc 'fix', 'Configure the UEM server to prohibit user installation of software by an administrator without the appropriate assigned permission for software installation.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37705r851587_chk'
  tag severity: 'medium'
  tag gid: 'V-234520'
  tag rid: 'SV-234520r879751_rule'
  tag stig_id: 'SRG-APP-000378-UEM-000248'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-37670r615204_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
