control 'SV-248678' do
  title 'OL 8 must enable a user session lock until that user reestablishes access using established identification and authentication procedures for command line sessions.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence. 
 
The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, OL 8 needs to provide users with the ability to manually invoke a session lock so users may secure their session should the need arise for them to temporarily vacate the immediate physical vicinity. 
 
Systemd, a core component of OL 8, has a variety of dependencies needed to function. One of those packages is the Keytable files and keyboard utilities (kbd.x86_64). This package provides the "vlock" binary, a utility used to lock one or several user virtual console sessions.

'
  desc 'check', 'Verify OL 8 has the "vlock" package installed by running the following command: 
 
$ sudo grep vlock /usr/bin/* 
 
Binary file /usr/bin/vlock matches 
 
If "vlock" is not installed, this is a finding.'
  desc 'fix', 'Install the "vlock" package, if it is not already installed, by running the following command: 
 
$ sudo yum install kbd.x86_64'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52112r779598_chk'
  tag severity: 'medium'
  tag gid: 'V-248678'
  tag rid: 'SV-248678r779600_rule'
  tag stig_id: 'OL08-00-020043'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-52066r779599_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
end
