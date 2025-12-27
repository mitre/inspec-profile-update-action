control 'SV-216096' do
  title 'The system must require passwords to contain no more than three consecutive repeating characters.'
  desc 'Complex passwords can reduce the likelihood of success of automated password-guessing attacks.'
  desc 'check', 'Check the MAXREPEATS setting.

# grep ^MAXREPEATS /etc/default/passwd

If the MAXREPEATS setting is greater than 3, this is a finding.'
  desc 'fix', 'The root role is required.
# pfedit /etc/default/passwd 

Locate the line containing:

MAXREPEATS

Change the line to read: 

MAXREPEATS=3'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17334r372670_chk'
  tag severity: 'low'
  tag gid: 'V-216096'
  tag rid: 'SV-216096r603268_rule'
  tag stig_id: 'SOL-11.1-040110'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17332r372671_fix'
  tag 'documentable'
  tag legacy: ['V-47993', 'SV-60865']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
