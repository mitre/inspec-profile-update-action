control 'SV-45911' do
  title 'Any X Windows host must write .Xauthority files.'
  desc '.Xauthority files ensure the user is authorized to access specific X Windows host. If .Xauthority files are not used, it may be possible to obtain unauthorized access to the X Windows host.'
  desc 'check', 'Check if the ‘xorg-x11’ package is installed:
# rpm –q xorg-x11
If the xorg-x11 package is not installed this finding does not apply.



Check for .Xauthority or .xauth files being utilized by looking for such files in the home directory of a user.

Procedure:
Verify Xwindows is used on the system. 
# egrep "^x:5.*X11" /etc/inittab
If no line is returned the boot process does not start Xwindows. If Xwindows is not configured to run, this rule is not applicable. 

Look for xauthority files in user home directory.
# cd ~someuser
# ls -la|egrep "(\\.Xauthority|\\.xauth) "

If the .Xauthority or .xauth (followed by apparently random characters) files do not exist, ask the SA if the user is using Xwindows. If the user is utilizing Xwindows and none of these files exist, this is a finding.'
  desc 'fix', 'The X Windows server package should not be needed on a System z virtual OE.  It can be removed to close this finding:
# rpm –e xorg-x11

If X Windows is required for some reason, ensure that the X Windows host is configured to write .Xauthority files into user home directories.  Edit the Xaccess file.  Ensure the line that writes the .Xauthority file is uncommented.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43219r2_chk'
  tag severity: 'medium'
  tag gid: 'V-850'
  tag rid: 'SV-45911r1_rule'
  tag stig_id: 'GEN005160'
  tag gtitle: 'GEN005160'
  tag fix_id: 'F-39290r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000297']
  tag nist: ['CM-2 b 2']
end
