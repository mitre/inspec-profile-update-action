control 'SV-227030' do
  title 'The system must not run an Internet Network News (INN) server.'
  desc 'Internet Network News (INN) servers access Usenet newsfeeds and store newsgroup articles.  INN servers use the Network News Transfer Protocol (NNTP) to transfer information from the Usenet to the server and from the server to authorized remote hosts.

If this function is necessary to support a valid mission requirement, its use must be authorized and approved in the system accreditation package.'
  desc 'check', '# ps -ef | egrep "innd|nntpd"

If an INN server is running, this is a finding.'
  desc 'fix', 'Disable the INN server.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29192r485444_chk'
  tag severity: 'medium'
  tag gid: 'V-227030'
  tag rid: 'SV-227030r603265_rule'
  tag stig_id: 'GEN006240'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29180r485445_fix'
  tag 'documentable'
  tag legacy: ['V-1023', 'SV-1023']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
