control 'SV-216073' do
  title 'Any X Windows host must write .Xauthority files.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host. If .Xauthority files are not used, it may be possible to obtain unauthorized access to the X Windows host.'
  desc 'check', 'If X Display Manager (XDM) is not used on the system, this is not applicable.

Determine if XDM is running.
Procedure:
# ps -ef | grep xdm

If X Display Manager (XDM) is not used on the system, this is not applicable.

Determine if XDM is running.
Procedure:
# ps -ef | grep xdm

Check for .Xauthority files being utilized by looking for such files in the home directory of a user that uses X.

Procedure:
# cd ~someuser
# ls -la .Xauthority

If the .Xauthority file does not exist, ask the SA if the user is using X Windows. If the user is utilizing X Windows and the .Xauthority file does not exist, this is a finding.'
  desc 'fix', 'Ensure the X Windows host is configured to write .Xauthority files into user home directories. 

Edit the Xaccess file. Ensure the line that writes the .Xauthority file is uncommented.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17311r372601_chk'
  tag severity: 'medium'
  tag gid: 'V-216073'
  tag rid: 'SV-216073r603268_rule'
  tag stig_id: 'SOL-11.1-020500'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17309r372602_fix'
  tag 'documentable'
  tag legacy: ['SV-75471', 'V-61003']
  tag cci: ['CCI-000297', 'CCI-000366']
  tag nist: ['CM-2 b 2', 'CM-6 b']
end
