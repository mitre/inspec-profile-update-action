control 'SV-215310' do
  title 'If Bourne / ksh shell is used, AIX must display logout messages.'
  desc 'If a user cannot explicitly end an operating system session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Information resources to which users gain access via authentication include, for example, local workstations and remote services. Logoff messages can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions, including, for example, remote login, information systems typically send logoff messages as final messages prior to terminating sessions.'
  desc 'check', %q(Verify users have a ".logout" file in their home directory:

# for home in `cut -d: -f6 /etc/passwd`; do ls -alL $home/.logout; done
-rwxr-----    1 root  system           297 Jan 29 09:47 /root/.logout
-rwxr-----    1 doejohn  staff        297 Jul 4 00:47 /home/doejohn/.logout

If an interactive user does not have their ".logout" file, this is a finding.

Verify that each ".logout" file identified above contains a logout message:

# cat <user_home_directory>/.logout
echo "You are being disconnected."
sleep 5

If the ".logout" file does not display a logout message, this is a finding.

Verify each users' ".profile" file calls "$HOME/.logout" while logging out:

# grep "trap '$HOME/.logout' EXIT " <user_home_directory>/.profile
trap '$HOME/.logout' EXIT

If the ".profile" file does not call "$HOME/.logout", this is a finding.)
  desc 'fix', %q(Create the ".logout" file if it does not exist.

Add the following two lines to ".logout" to display a logout message and sleep for "5" seconds:
echo "You are being disconnected."
sleep 5

Create, or modify, ".profile" to include the following line:
trap '$HOME/.logout' EXIT)
  impact 0.3
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16508r294381_chk'
  tag severity: 'low'
  tag gid: 'V-215310'
  tag rid: 'SV-215310r508663_rule'
  tag stig_id: 'AIX7-00-002129'
  tag gtitle: 'SRG-OS-000281-GPOS-00111'
  tag fix_id: 'F-16506r294382_fix'
  tag 'documentable'
  tag legacy: ['SV-101595', 'V-91497']
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
