control 'SV-243456' do
  title 'In a Windows PAW, administrator accounts used for maintaining the PAW must be separate from administrative accounts used to manage high-value IT resources.'
  desc 'Note: PAW accounts used to manage high-value IT resources have privileged rights on managed systems but no administrative or maintenance rights on the PAW. They only have user rights on the PAW. PAW administrative/maintenance accounts only have administrative rights on a PAW and are used only to perform administrative functions on the PAW.  PAW administrative/maintenance accounts are the only admin accounts that have admin rights on a PAW.  It is not required that PAW administrative/maintenance accounts be organized by tier.

The PAW platform should be protected from high-value IT resource administrators accidently or deliberately modifying the security settings of the PAW. Therefore, high-value IT resource administrators must not have the ability to perform maintenance functions on the PAW platform. Separate PAW admin accounts must be set up that only have rights to manage PAW platforms.

PAW administrators have the capability to compromise Domain Admin accounts; therefore, personnel assigned as PAW administrators must be the most trusted and experienced administrators within an organization, at least equal to personnel assigned as domain administrators.'
  desc 'check', 'Verify at least one group has been set up in Active Directory (usually Tier 0) for administrators responsible for maintaining PAW workstations (for example, PAW Maintenance group).

Verify no administrator account or administrator account group has been assigned to both the group of PAW workstation administrators and any group for administrators of high-value IT resources.

If separate PAW administrator groups and administrators of high-value IT resources have not been set up, this is a finding.

If a member of any group of PAW maintenance administrators is also a member of any group of administrators of high-value IT resources, this is a finding.'
  desc 'fix', 'Set up separate domain administrative accounts to manage PAWs from domain administrative accounts used to manage high-value IT resources. Each of these accounts is not to be used for any other purpose. 

Note: Personnel assigned as PAW administrators should be the most trusted and experienced administrators within an organization.'
  impact 0.5
  ref 'DPMS Target Windows PAW'
  tag check_id: 'C-46731r722937_chk'
  tag severity: 'medium'
  tag gid: 'V-243456'
  tag rid: 'SV-243456r722939_rule'
  tag stig_id: 'WPAW-00-001500'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-46688r722938_fix'
  tag 'documentable'
  tag legacy: ['V-78173', 'SV-92879']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
