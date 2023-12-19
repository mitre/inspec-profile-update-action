control 'SV-214867' do
  title 'The macOS system must not have a root account.'
  desc 'To assure individual accountability and prevent unauthorized access, organizational users must be individually identified and authenticated.'
  desc 'check', 'To check if the root account is disabled, run the following command:

defaults read /var/db/dslocal/nodes/Default/users/root.plist passwd
(
"*"
)

The output should be a single asterisk in quotes, as seen above. If the output is as follow, this is a finding:

(
"********"
)'
  desc 'fix', 'Disable the root account with the following command:

/usr/sbin/dsenableroot -d'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16067r397173_chk'
  tag severity: 'medium'
  tag gid: 'V-214867'
  tag rid: 'SV-214867r609363_rule'
  tag stig_id: 'AOSX-13-000553'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16065r397174_fix'
  tag 'documentable'
  tag legacy: ['V-81613', 'SV-96327']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
