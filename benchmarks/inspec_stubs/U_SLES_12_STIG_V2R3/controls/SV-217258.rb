control 'SV-217258' do
  title 'The SUSE operating system must not have the telnet-server package installed.'
  desc 'It is detrimental for SUSE operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

SUSE operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions and functions).

Examples of nonessential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but which cannot be disabled.

'
  desc 'check', 'Verify the telnet-server package is not installed on the SUSE operating system.

Check that the telnet-server package is not installed on the SUSE operating system by running the following command:

# zypper se telnet-server

If the telnet-server package is installed, this is a finding.'
  desc 'fix', 'Remove the telnet-server package from the SUSE operating system by running the following command:

# sudo zypper remove telnet-server'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18486r369930_chk'
  tag severity: 'medium'
  tag gid: 'V-217258'
  tag rid: 'SV-217258r603262_rule'
  tag stig_id: 'SLES-12-030000'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-18484r369931_fix'
  tag satisfies: ['SRG-OS-000074-GPOS-00042', 'SRG-OS-000095-GPOS-00049']
  tag 'documentable'
  tag legacy: ['SV-92125', 'V-77429']
  tag cci: ['CCI-000197', 'CCI-000381']
  tag nist: ['IA-5 (1) (c)', 'CM-7 a']
end
