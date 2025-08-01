control 'SV-252513' do
  title 'The macOS system must enforce access restrictions.'
  desc 'Failure to provide logical access restrictions associated with changes to system configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the operating system can have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to operating system components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'To check that the system is configured to disable the guest account, run the following command:

# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableGuestAccount

If the result is null or not "DisableGuestAccount = 1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Login Window Policy" configuration profile.'
  impact 0.7
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55969r816351_chk'
  tag severity: 'high'
  tag gid: 'V-252513'
  tag rid: 'SV-252513r816353_rule'
  tag stig_id: 'APPL-12-002063'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-55919r816352_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
