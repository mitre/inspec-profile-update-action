control 'SV-257189' do
  title 'The macOS system must be configured to disable the UUCP service.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems can provide a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The system must not have the UUCP service active.'
  desc 'check', 'Verify the macOS system is configured to disable the UUCP service with the following command:

/bin/launchctl print-disabled system | /usr/bin/grep com.apple.uucp

"com.apple.uucp" => disabled

If the results are not "com.apple.uucp => disabled", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable the UUCP service with the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.uucp

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60874r905198_chk'
  tag severity: 'medium'
  tag gid: 'V-257189'
  tag rid: 'SV-257189r905200_rule'
  tag stig_id: 'APPL-13-002006'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-60815r905199_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
