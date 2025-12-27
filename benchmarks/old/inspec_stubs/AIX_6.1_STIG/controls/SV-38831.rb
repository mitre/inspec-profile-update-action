control 'SV-38831' do
  title 'The system must use available memory address randomization techniques.'
  desc 'Successful exploitation of buffer overflow vulnerabilities relies in some measure to having a predictable address structure of the executing program. Address randomization techniques reduce the probability of a successful exploit.'
  desc 'check', 'Running the sedmgr command without any options will show the settings currently in effect.   

#sedmgr

If the value returned for the sedmgr mode is off,  this is a finding.'
  desc 'fix', 'Configure the system to use any available memory address randomization techniques.  Recommended settings are either to enable stack execution disablement for all suid files or select system executables.  

Set sedmgr to enforce on selected files and terminate processes violating stack execution boundaries.
# sedmgr -m select -o off

OR

Set sedmgr to enforce on setid files and terminate processes violating stack execution boundaries.
# sedmgr -m setidfiles -o off

After a global system change to the sed,  the system should be rebooted.
# shutdown -Fr'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37086r1_chk'
  tag severity: 'low'
  tag gid: 'V-22576'
  tag rid: 'SV-38831r1_rule'
  tag stig_id: 'GEN008420'
  tag gtitle: 'GEN008420'
  tag fix_id: 'F-32358r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
