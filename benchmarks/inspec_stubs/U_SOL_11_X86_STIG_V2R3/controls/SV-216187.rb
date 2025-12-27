control 'SV-216187' do
  title 'All user accounts must be configured to use a home directory that exists.'
  desc %q(If the user's home directory does not exist, the user will be placed in "/" and will not be able to write any files or have local environment variables set.)
  desc 'check', %q(The root role is required.

Check if a GUI is installed.

Determine the OS version you are currently securing:. 
# uname –v

For Solaris 11, 11.1, 11.2, and 11.3:
# pkg info gdm
# pkg info coherence-26
# pkg info coherence-27

If none of these packages are installed on the system, then no GUI is present.
For Solaris 11.4 or newer:
# pkg info gdm

If gdm is not installed on the system, then no GUI is present.

# pkg info uucp

uucp is no longer installed by default starting in 11.4 and is deprecated. 

For all versions, check that all users' home directories exist.

# pwck

Accounts with no home directory will output "Login directory not found".

If no GUI is present, then "gdm" and "upnp" accounts should generate errors. On all systems, with uucp package installed, the "uucp" and "nuucp" accounts should generate errors.

If users' home directories do not exist, this is a finding.)
  desc 'fix', 'The root role is required.

Work with users identified in the check step to determine the best course of action in accordance with site policy. This generally means deleting the user account or creating a valid home directory.'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17425r372943_chk'
  tag severity: 'low'
  tag gid: 'V-216187'
  tag rid: 'SV-216187r603268_rule'
  tag stig_id: 'SOL-11.1-070080'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17423r372944_fix'
  tag 'documentable'
  tag legacy: ['SV-60977', 'V-48105']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
