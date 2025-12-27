control 'SV-234247' do
  title 'The UEM Agent must be configured to perform one of the following actions upon an attempt to unenroll the mobile device from management: 
-prevent the unenrollment from occurring
-wipe the device to factory default settings
-wipe the work profile with all associated applications and data.'
  desc 'Access control of mobile devices to DoD sensitive information or access to DoD networks must be controlled so that DoD data will not be compromised. The primary method of access control of mobile devices is via enrollment of authorized mobile devices on the UEM server. Therefore, the UEM server must have the capability to enforce a policy for this control.

'
  desc 'check', 'Verify the UEM Agent performs one of the following actions upon an attempt to unenroll the mobile device from management: 
-prevent the unenrollment from occurring
-wipe the device to factory default settings
-wipe the work profile with all associated applications and data.

If the UEM Agent does not perform one of the following actions upon an attempt to unenroll the mobile device from management: 
-prevent the unenrollment from occurring
-wipe the device to factory default settings
-wipe the work profile with all associated applications and data
this is a finding.'
  desc 'fix', 'Configure the UEM Agent to perform one of the following actions upon an attempt to unenroll the mobile device from management: 
-prevent the unenrollment from occurring
-wipe the device to factory default settings
-wipe the work profile with all associated applications and data.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37432r617393_chk'
  tag severity: 'medium'
  tag gid: 'V-234247'
  tag rid: 'SV-234247r617393_rule'
  tag stig_id: 'SRG-APP-000516-UEM-100011'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37397r612048_fix'
  tag satisfies: ['FMT_UNR_EXT.1.1']
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
