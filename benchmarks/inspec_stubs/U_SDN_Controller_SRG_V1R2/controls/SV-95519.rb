control 'SV-95519' do
  title 'The SDN controller must be configured to prohibit user installation of software without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.

Application functionality will vary, and while users are not permitted to install unapproved applications, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. 

The application must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization. 

This requirement applies, for example, to applications that provide the ability to extend application functionality (e.g., plug-ins, add-ons) and software management applications.'
  desc 'check', 'Review documentation of non-administrative users who have been given access permissions to install, modify, or replace software modules within the SDN controller framework. Review the SDN controller configuration to determine that only authorized users have the permissions to install, modify, or replace software modules. 

If the SDN controller is not configured to revoke unauthorized attempts to install, modify, or replace software modules, this is a finding.'
  desc 'fix', 'Document the approval for non-administrative users who require the ability to install, modify, or replace software modules within the SDN controller framework. Configure the SDN controller to revoke the installation of software modules by any unapproved permissions or access levels.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80545r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80809'
  tag rid: 'SV-95519r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001090'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87663r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
