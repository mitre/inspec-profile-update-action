control 'SV-12655' do
  title 'Annual reviews must be performed on all Releasable Local Area Network (REL LAN) environments.'
  desc 'The ISSM will ensure Releasable Local Area Network (REL LAN) reviews are performed annually.'
  desc 'check', 'Have the ISSM disclose documentation that a REL LAN review has been performed annually.

If annual reviews are not being performed, this is a finding.'
  desc 'fix', 'The ISSM will document REL LAN reviews being performed annually.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-8119r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12102'
  tag rid: 'SV-12655r2_rule'
  tag stig_id: 'NET1816'
  tag gtitle: 'Annual reviews are not being performed on REL LAN'
  tag fix_id: 'F-11391r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
