control 'SV-40029' do
  title 'SWLAN must be rekeyed at least every 90 days.'
  desc 'The longer a key remains in use, the more likely it will be compromised.   If an adversary can compromise an SWLAN key, then it can obtain classified information.'
  desc 'check', 'Detailed Policy Requirements:

SWLAN system will be rekeyed at least every 90 days.

Check Procedures:

Interview IAO and obtain the site’s procedures for rekeying the WLAN.  Mark a finding if the procedures do not exist or they do not include a requirement to rekey at least every 90 days.'
  desc 'fix', 'Write and implement rekeying procedures that specify the keys must be changed at least every 90 days.'
  impact 0.7
  ref 'DPMS Target L3 KOV-26 Talon'
  tag check_id: 'C-39044r1_chk'
  tag severity: 'high'
  tag gid: 'V-30369'
  tag rid: 'SV-40029r1_rule'
  tag stig_id: 'WIR0231'
  tag gtitle: 'SWLAN rekeying'
  tag fix_id: 'F-34145r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECWN-1'
end
