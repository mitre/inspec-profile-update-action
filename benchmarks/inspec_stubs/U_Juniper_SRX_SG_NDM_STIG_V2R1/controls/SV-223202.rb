control 'SV-223202' do
  title 'The Juniper SRX Services Gateway must implement logon roles to ensure only authorized roles are allowed to install software and updates.'
  desc 'Allowing anyone to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. This requirement applies to code changes and upgrades for all network devices.

For example audit admins and the account of last resort are not allowed to perform this task.'
  desc 'check', 'To verify role-based access control has been configured, view the settings for each login class defined.

[edit]
show system login

View all login classes to see which roles are assigned the "Maintenance" or "request system software add" permissions. 

If login classes for user roles that are not authorized to install and update software are configured, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to allow only the ISSM user account (or administrators/roles appointed by the ISSM) to select which auditable events are to be audited. To ensure this is the case, each ISSM-appointed role on the AAA must be configured for least privilege using the following stanzas for each role.

[edit]
show system login

Use the delete command or retype the command to remove the permission "Maintenance" or "request system software add" from any class that is not authorized to upgrade software on the device. An explicitly Deny for the command "request system software add" can also be used if some Maintenance commands are permitted.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24875r513293_chk'
  tag severity: 'medium'
  tag gid: 'V-223202'
  tag rid: 'SV-223202r513295_rule'
  tag stig_id: 'JUSX-DM-000077'
  tag gtitle: 'SRG-APP-000378-NDM-000302'
  tag fix_id: 'F-24863r513294_fix'
  tag 'documentable'
  tag legacy: ['SV-80975', 'V-66485']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
