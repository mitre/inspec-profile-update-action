control 'SV-248898' do
  title 'The graphical display manager must not be installed on OL 8 unless approved.'
  desc 'Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. X Windows has a long history of security vulnerabilities and will not be used unless approved and documented.'
  desc 'check', 'Verify that if the system has a display server installed, it is authorized. 
 
Check for the display server package with the following example command: 
 
$ sudo rpm -qa | grep xorg | grep server 
 
Ask the System Administrator if use of the display server is an operational requirement. 
 
If the use of a display server on the system is not documented with the Information System Security Officer (ISSO), this is a finding.'
  desc 'fix', 'Document the requirement for a display server with the ISSO or remove the related packages with the following example command: 
 
$ sudo rpm -e xorg-x11-server-common'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52332r780258_chk'
  tag severity: 'medium'
  tag gid: 'V-248898'
  tag rid: 'SV-248898r780260_rule'
  tag stig_id: 'OL08-00-040320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52286r780259_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
