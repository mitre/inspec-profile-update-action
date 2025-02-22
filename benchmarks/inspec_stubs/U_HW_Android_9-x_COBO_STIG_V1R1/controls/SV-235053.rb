control 'SV-235053' do
  title 'The Honeywell Android Pie must wipe all data upon unenrollment from MDM.'
  desc 'When a mobile device is no longer going to be managed by MDM technologies, its protected/sensitive data must be sanitized because it will no longer be protected by the MDM software, so it is at much greater risk of unauthorized access and disclosure. At least one of the two options must be selected.

SFR ID: FMT_SMF_EXT.2.1'
  desc 'check', 'Review Honeywell Android device configuration settings to determine if the mobile device is configured to prohibit the user from unenrolling the Honeywell device from MDM management.

This validation procedure is performed only on the MDM Administration console. 

On the MDM console:
Ensure "Disallow remove managed profile" is enabled.

If the MDM console device policy is not configured to prohibit the user from unenrolling the Honeywell device from MDM management, this is a finding.'
  desc 'fix', 'On the MDM console:
Enable "Disallow remove managed profile".

Prior to unenrollment, the MDM administrator should issue a factory reset to ensure all data is wiped by doing the following in the MDM console: 
Wipe data.'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38241r623069_chk'
  tag severity: 'medium'
  tag gid: 'V-235053'
  tag rid: 'SV-235053r626530_rule'
  tag stig_id: 'HONW-09-007150'
  tag gtitle: 'PP-MDF-302500'
  tag fix_id: 'F-38204r623070_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-001033']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'MP-6 (3)']
end
