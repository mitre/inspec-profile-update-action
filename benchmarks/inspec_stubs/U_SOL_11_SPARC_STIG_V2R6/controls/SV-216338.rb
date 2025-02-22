control 'SV-216338' do
  title 'The system must prevent the use of dictionary words for passwords.'
  desc 'The use of common words in passwords simplifies password-cracking attacks.'
  desc 'check', 'Check /etc/default/passwd for dictionary check configuration.

# grep ^DICTION /etc/default/passwd

If the DICTIONLIST or DICTIONDBDIR settings are not present and are not set to:

DICTIONLIST=/usr/share/lib/dict/words
DICTIONDBDIR=/var/passwd

this is a finding.

Determine if the target files exist.

# ls -l /usr/share/lib/dict/words /var/passwd

If the files defined by DICTIONLIST or DICTIONBDIR are not present or are empty, this is a finding.'
  desc 'fix', 'The root role is required.

# pfedit /etc/default/passwd

Insert the lines:

DICTIONLIST=/usr/share/lib/dict/words
DICTIONDBDIR=/var/passwd

Generate the password dictionary by running the mkpwdict command.

# mkpwdict -s /usr/share/lib/dict/words'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17574r371102_chk'
  tag severity: 'medium'
  tag gid: 'V-216338'
  tag rid: 'SV-216338r603267_rule'
  tag stig_id: 'SOL-11.1-040190'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17572r371103_fix'
  tag 'documentable'
  tag legacy: ['V-48053', 'SV-60925']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
