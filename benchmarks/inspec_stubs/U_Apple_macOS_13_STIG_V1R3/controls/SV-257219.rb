control 'SV-257219' do
  title 'The macOS system must disable the guest account.'
  desc 'Failure to provide logical access restrictions associated with changes to system configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the operating system can have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to operating system components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Verify the macOS system is configured to disable the guest account with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "GuestAccount"

DisableGuestAccount = 1;
EnableGuestAccount = 0;

If the result are not "DisableGuestAccount = 1" and "EnableGuestAccount = 0", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable the guest account by installing the "Login Window Policy" configuration profile.'
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60904r922874_chk'
  tag severity: 'high'
  tag gid: 'V-257219'
  tag rid: 'SV-257219r922875_rule'
  tag stig_id: 'APPL-13-002063'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-60845r905289_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
