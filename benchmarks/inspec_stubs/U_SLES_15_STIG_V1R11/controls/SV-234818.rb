control 'SV-234818' do
  title 'The SUSE operating system must not have the telnet-server package installed.'
  desc 'It is detrimental for SUSE operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked, and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

SUSE operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions and functions).

Examples of nonessential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but which cannot be disabled.

'
  desc 'check', 'Verify the telnet-server package is not installed on the SUSE operating system.

Check that the telnet-server package is not installed on the SUSE operating system by running the following command:

> zypper info telnet-server | grep Installed

If the telnet-server package is installed, this is a finding.'
  desc 'fix', 'Remove the telnet-server package from the SUSE operating system by running the following command:

> sudo zypper remove telnet-server'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38006r618723_chk'
  tag severity: 'high'
  tag gid: 'V-234818'
  tag rid: 'SV-234818r877396_rule'
  tag stig_id: 'SLES-15-010180'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-37969r618724_fix'
  tag satisfies: ['SRG-OS-000074-GPOS-00042', 'SRG-OS-000095-GPOS-00049']
  tag 'documentable'
  tag cci: ['CCI-000197', 'CCI-000381']
  tag nist: ['IA-5 (1) (c)', 'CM-7 a']
end
