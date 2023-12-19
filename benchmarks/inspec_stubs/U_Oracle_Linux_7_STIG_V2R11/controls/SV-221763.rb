control 'SV-221763' do
  title 'The Oracle Linux operating system must not have the telnet-server package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Verify the operating system is configured to disable non-essential capabilities. The most secure way of ensuring a non-essential capability is disabled is not to install the capability.

The telnet service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session.

If a privileged user were to log on using this service, the privileged user password could be compromised. 

Check to see if the telnet-server package is installed with the following command:

# yum list installed telnet-server

If the telnet-server package is installed, this is a finding.'
  desc 'fix', 'Configure the operating system to disable non-essential capabilities by removing the telnet-server package from the system with the following command:

# yum remove telnet-server'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23478r419361_chk'
  tag severity: 'high'
  tag gid: 'V-221763'
  tag rid: 'SV-221763r603260_rule'
  tag stig_id: 'OL07-00-021710'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-23467r419362_fix'
  tag 'documentable'
  tag legacy: ['SV-108369', 'V-99265']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
