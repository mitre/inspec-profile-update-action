control 'SV-32638' do
  title 'Administrative users and groups with access privilege to the web server must be documented.'
  desc "There are typically several individuals and groups involved in running a production web-site. In most cases, several types of users on a web server can be identified, such as, SA's, Web Managers, Auditors, Authors, Developers, and the Clients.  Nonetheless, only necessary user and administrative accounts will be allowed on the web server.  Accounts will be restricted to those who are necessary to maintain web services, review the server’s operation and the OS.  Owing to the sensitivity of web servers, a detailed record of these accounts must be maintained."
  desc 'check', "Determine if the local sites' documentation matches an examination of the privileged IDs on the server. Using User Manager, User Manager for Domains, or Local Users and Groups, examine user accounts to verify the above information. If documentation does not exist for users and groups found on the server, this is a finding."
  desc 'fix', 'Document the administrative users and groups which have access rights to the web server in the website SOP or an equivalent document.'
  impact 0.3
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-29090r1_chk'
  tag severity: 'low'
  tag gid: 'V-2257'
  tag rid: 'SV-32638r2_rule'
  tag stig_id: 'WA120 IIS7'
  tag gtitle: 'WA120'
  tag fix_id: 'F-26819r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Manager', 'Web Administrator']
end
