control 'SV-215336' do
  title 'AIX must remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Run the following command to check any installed components that are in APPLY state:
# lslpp -cl | grep :APPLIED:

If the command returns any entries, this is a finding.'
  desc 'fix', 'Run the following command to commit any applied components:
# installp -c all'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16534r294459_chk'
  tag severity: 'medium'
  tag gid: 'V-215336'
  tag rid: 'SV-215336r508663_rule'
  tag stig_id: 'AIX7-00-003028'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-16532r294460_fix'
  tag 'documentable'
  tag legacy: ['SV-101661', 'V-91563']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
