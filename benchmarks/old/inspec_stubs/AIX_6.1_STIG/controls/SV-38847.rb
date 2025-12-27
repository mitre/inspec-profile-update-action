control 'SV-38847' do
  title 'All shell files must be owned by root or bin.'
  desc 'If shell files are owned by users other than root or bin, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'check', 'Obtain a list of system shells from /etc/security/login.cfg and check the ownership of these shells.
Procedure:
#grep shells /etc/security/login.cfg | grep -v \\* | cut -f 2 -d = | sed s/,/\\ /g | xargs -n1 ls -l
If any shell is not owned by root or bin, this is a finding.

Obtain a list of  system shells from /etc/shells and check the  ownership of these shells.
Procedure:
#cat /etc/shells | xargs -n1 ls -l
If any shell is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of the shell with incorrect ownership.
# chown root < shell >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37840r1_chk'
  tag severity: 'medium'
  tag gid: 'V-921'
  tag rid: 'SV-38847r1_rule'
  tag stig_id: 'GEN002200'
  tag gtitle: 'GEN002200'
  tag fix_id: 'F-33103r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
