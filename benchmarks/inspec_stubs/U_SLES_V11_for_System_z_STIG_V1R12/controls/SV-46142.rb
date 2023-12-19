control 'SV-46142' do
  title 'The system must not run an Internet Network News (INN) server.'
  desc 'INN servers access Usenet newsfeeds and store newsgroup articles.  INN servers use the Network News Transfer Protocol (NNTP) to transfer information from the Usenet to the server and from the server to authorized remote hosts.

If this function is necessary to support a valid mission requirement, its use must be authorized and approved in the system accreditation package.'
  desc 'check', '# ps -ef | egrep "innd|nntpd"

If an Internet Network News server is running, this is a finding.'
  desc 'fix', 'Disable the INN server.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43403r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1023'
  tag rid: 'SV-46142r1_rule'
  tag stig_id: 'GEN006240'
  tag gtitle: 'GEN006240'
  tag fix_id: 'F-39485r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
