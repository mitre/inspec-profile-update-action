control 'SV-239077' do
  title 'The Photon operating system must set a session inactivity timeout of 15 minutes or less.'
  desc 'A session timeout is an action taken when a session goes idle for any reason. Rather than relying on the user to manually disconnect their session prior to going idle, the Photon operating system must be able to identify when a session has idled and take action to terminate the session.

'
  desc 'check', 'At the command line, execute the following command:

# cat /etc/profile.d/tmout.sh

Expected result:

TMOUT=900
readonly TMOUT 
export TMOUT
mesg n 2>/dev/null

If the file "tmout.sh" does not exist or the output does not look like the expected result, this is a finding.'
  desc 'fix', 'Open /etc/profile.d/tmout.sh with a text editor and set its content to the following: 

TMOUT=900
readonly TMOUT 
export TMOUT
mesg n 2>/dev/null'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42288r675037_chk'
  tag severity: 'medium'
  tag gid: 'V-239077'
  tag rid: 'SV-239077r675039_rule'
  tag stig_id: 'PHTN-67-000005'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-42247r675038_fix'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000126-GPOS-00066', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag cci: ['CCI-000057', 'CCI-000879', 'CCI-002361']
  tag nist: ['AC-11 a', 'MA-4 e', 'AC-12']
end
