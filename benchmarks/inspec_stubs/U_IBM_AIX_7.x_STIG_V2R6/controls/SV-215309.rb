control 'SV-215309' do
  title 'If bash is used, AIX must display logout messages.'
  desc 'If a user cannot explicitly end an operating system session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Information resources to which users gain access via authentication include, for example, local workstations and remote services. Logoff messages can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions, including, for example, remote login, information systems typically send logoff messages as final messages prior to terminating sessions.'
  desc 'check', 'Identify any users that are using the BASH shell:

# cut -d: -f1,7 /etc/passwd | grep -i bash
doejohn:/bin/bash

If no users are assigned the BASH shell, this is Not Applicable

Verify that each BASH shell user has a ".bash_logout" file:

# for home in `cut -d: -f6 /etc/passwd`; do ls -alL $home/.bash_logout; done
-rwxr-----    1 doejohn  staff           297 Jan 29 09:47 /home/doejohn/.bash_logout

If a user does not have their ".bash_logout" file, this is a finding.

Verify that each ".bash_logout" file identified above contains a logout message:

# cat <user_home_directory>/.bash_logout
echo "You are being disconnected."
sleep 5 

If the ".bash_logout" file is not configured to display a logout message, this is a finding.'
  desc 'fix', 'Create the ".bash_logout" file if it does not exist.

Add the following two lines to ".bash_logout" to display a logout message and sleep for "5" seconds:
echo "You are being disconnected."
sleep 5'
  impact 0.3
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16507r294378_chk'
  tag severity: 'low'
  tag gid: 'V-215309'
  tag rid: 'SV-215309r508663_rule'
  tag stig_id: 'AIX7-00-002128'
  tag gtitle: 'SRG-OS-000281-GPOS-00111'
  tag fix_id: 'F-16505r294379_fix'
  tag 'documentable'
  tag legacy: ['SV-101593', 'V-91495']
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
