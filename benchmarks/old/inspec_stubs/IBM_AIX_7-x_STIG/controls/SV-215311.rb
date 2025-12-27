control 'SV-215311' do
  title 'If csh/tcsh shell is used, AIX must display logout messages.'
  desc 'If a user cannot explicitly end an operating system session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Information resources to which users gain access via authentication include, for example, local workstations and remote services. Logoff messages can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions, including, for example, remote login, information systems typically send logoff messages as final messages prior to terminating sessions.'
  desc 'check', 'Check if users have their "$HOME/.logout" files.

If a user does not have their ".logout" file, or the ".logout" file does not display a logout message, this is a finding.'
  desc 'fix', 'Create the ".logout" file if it does not exist.

Add the following two lines to ".logout" to display a logout message and sleep for "5" seconds:
echo "You are being disconnected."
sleep 5'
  impact 0.3
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16509r294384_chk'
  tag severity: 'low'
  tag gid: 'V-215311'
  tag rid: 'SV-215311r853478_rule'
  tag stig_id: 'AIX7-00-002130'
  tag gtitle: 'SRG-OS-000281-GPOS-00111'
  tag fix_id: 'F-16507r294385_fix'
  tag 'documentable'
  tag legacy: ['SV-101597', 'V-91499']
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
