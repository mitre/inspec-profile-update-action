control 'SV-239125' do
  title 'The Photon operating system must set an inactivity timeout value for non-interactive sessions.'
  desc 'A session timeout is an action taken when a session goes idle for any reason. Rather than relying on the user to manually disconnect their session prior to going idle, the Photon operating system must be able to identify when a session has idled and take action to terminate the session.'
  desc 'check', 'At the command line, execute the following command:

# grep TMOUT /etc/bash.bashrc

Expected result:

TMOUT=900
readonly TMOUT
export TMOUT

If the file does not exist or the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/bash.bashrc with a text editor and add the following to the end:

TMOUT=900
readonly TMOUT
export TMOUT'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42336r675181_chk'
  tag severity: 'medium'
  tag gid: 'V-239125'
  tag rid: 'SV-239125r856043_rule'
  tag stig_id: 'PHTN-67-000054'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-42295r675182_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
