control 'SV-1023' do
  title 'The system must not run an Internet Network News (INN) server.'
  desc 'Internet Network News (INN) servers access Usenet newsfeeds and store newsgroup articles.  INN servers use the Network News Transfer Protocol (NNTP) to transfer information from the Usenet to the server and from the server to authorized remote hosts.

If this function is necessary to support a valid mission requirement, its use must be authorized and approved in the system accreditation package.'
  desc 'fix', 'Disable the INN server.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-1023'
  tag rid: 'SV-1023r2_rule'
  tag stig_id: 'GEN006240'
  tag gtitle: 'GEN006240'
  tag fix_id: 'F-1177r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
