control 'SV-218651' do
  title 'The system must not run an Internet Network News (INN) server.'
  desc 'INN servers access Usenet newsfeeds and store newsgroup articles.  INN servers use the Network News Transfer Protocol (NNTP) to transfer information from the Usenet to the server and from the server to authorized remote hosts.

If this function is necessary to support a valid mission requirement, its use must be authorized and approved in the system accreditation package.'
  desc 'check', '# ps -ef | egrep "innd|nntpd"

If an Internet Network News server is running, this is a finding.'
  desc 'fix', 'Disable the INN server.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20126r562894_chk'
  tag severity: 'medium'
  tag gid: 'V-218651'
  tag rid: 'SV-218651r603259_rule'
  tag stig_id: 'GEN006240'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20124r562895_fix'
  tag 'documentable'
  tag legacy: ['V-1023', 'SV-63965']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
