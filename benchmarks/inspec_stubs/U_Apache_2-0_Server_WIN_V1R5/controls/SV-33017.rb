control 'SV-33017' do
  title 'Administrative users and groups that have access rights to the web server must be documented.'
  desc 'There are typically several individuals and groups that are involved in running a production web site. In most cases, we can identify several types of users on a web server. These are the System Administrators (SAs), Web Managers, Auditors, Authors, Developers, and the Clients.  Accounts will be restricted to those who are necessary to maintain web services, review the server’s operation, and the operating system. A detailed record of these accounts must be maintained.'
  desc 'check', 'Proposed Questions:

How many user accounts are associated with the web site operation and maintenance?
Where are these accounts documented? 

Working with the SA or the web administrator, determine if the documentation matches an examination of the privileged IDs on the server. Using User Manager, User Manager for Domains, or Local Users and Groups, examine user accounts to verify the above information. Query the SA or the Web Manager regarding the use of each account and each group found on the server.

If the documentation does not match the users and groups found on the server, this is a finding.'
  desc 'fix', 'Document the administrative users and groups which have access rights to the web server in the site SOP or equivalent document.'
  impact 0.3
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33699r1_chk'
  tag severity: 'low'
  tag gid: 'V-2257'
  tag rid: 'SV-33017r1_rule'
  tag stig_id: 'WA120 W22'
  tag gtitle: 'WA120'
  tag fix_id: 'F-29327r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
end
