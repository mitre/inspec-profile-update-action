control 'SV-237619' do
  title 'The SUSE operating system must not have the vsftpd package installed if not required for operational support.'
  desc 'It is detrimental for SUSE operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked, and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

SUSE operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions and functions).

Examples of nonessential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but which cannot be disabled.'
  desc 'check', 'Verify the vsftpd package is not installed on the SUSE operating system.

Check that the vsftpd package is not installed on the SUSE operating system by running the following command:

> zypper info vsftpd | grep Installed

If "vsftpd" is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Document the "vsftpd" package with the ISSO as an operational requirement or remove it from the system with the following command:

> sudo zypper remove vsftpd'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-40838r646818_chk'
  tag severity: 'medium'
  tag gid: 'V-237619'
  tag rid: 'SV-237619r877396_rule'
  tag stig_id: 'SLES-12-030011'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-40801r646819_fix'
  tag 'documentable'
  tag cci: ['CCI-000197', 'CCI-000381']
  tag nist: ['IA-5 (1) (c)', 'CM-7 a']
end
