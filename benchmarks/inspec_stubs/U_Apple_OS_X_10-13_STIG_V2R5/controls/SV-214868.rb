control 'SV-214868' do
  title 'The macOS system must not have a guest account.'
  desc 'Only authorized individuals should be allowed to obtain access to operating system components. Permitting access via a guest account provides unauthenticated access to any person.'
  desc 'check', "To check if the guest user exists, run the following command:

dscl . list /Users | grep -i Guest

To verify that Guest user cannot unlock volume, run the following command:

fdesetup list

To check if the system is configured to prohibit user installation of software, first check to ensure the Parental Controls are enabled with the following command:
/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(DisableGuestAccount | EnableGuestAccount)’

If the result is null or not:
DisableGuestAccount = 1;
EnableGuestAccount = 0;
This is a finding."
  desc 'fix', 'Remove the guest user with the following command:

sudo dscl . delete /Users/Guest

"This can also be managed with "Login Window Policy" configuration profile.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16068r397176_chk'
  tag severity: 'high'
  tag gid: 'V-214868'
  tag rid: 'SV-214868r609363_rule'
  tag stig_id: 'AOSX-13-000554'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-16066r397177_fix'
  tag 'documentable'
  tag legacy: ['SV-96329', 'V-81615']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
