control 'SV-241798' do
  title 'Jamf Pro EMM must be maintained at a supported version.'
  desc 'The MDM/EMM vendor maintains specific product versions for a specific period of time. MDM/EMM server versions no longer supported by the vendor will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

SFR ID: FPT_TUD_EXT.1.1, FPT_TUD_EXT.1.2'
  desc 'check', 'Verify the installed version of Jamf Pro EMM is currently supported.

On the Jamf Pro console do the following to determine the version number of the server:
1. Log in to the console.
2. View the version number listed in the upper left corner.

List of current supported versions:
v10.18 (End of Support Date: TBD
v10.17 (TBD)
v10.16 (TBD)
v10.15 (TBD)
v10.14 (TBD)
v10.13.1 (TBD)

If the displayed Jamf Pro server version is not currently supported or is not a newer version than on the list above, this is a finding.'
  desc 'fix', 'Update the Jamf Pro EMM to a supported version (see list below) or newer version.
v10.18 (End of Support Date: TBD
v10.17 (TBD)
v10.16 (TBD)
v10.15 (TBD)
v10.14 (TBD)
v10.13.1 (TBD)'
  impact 0.7
  ref 'DPMS Target Jamf Pro v10-x EMM'
  tag check_id: 'C-45074r685146_chk'
  tag severity: 'high'
  tag gid: 'V-241798'
  tag rid: 'SV-241798r879887_rule'
  tag stig_id: 'JAMF-10-000700'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-45033r685147_fix'
  tag 'documentable'
  tag legacy: ['SV-108701', 'V-99597']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
