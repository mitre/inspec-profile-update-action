control 'SV-207580' do
  title 'The core BIND 9.x server files must be owned by the root or BIND 9.x process account.'
  desc 'Discretionary Access Control (DAC) is based on the premise that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. In a DNS implementation, DAC should be granted to a minimal number of individuals and objects because DNS does not interact directly with users and users do not store and share data with the DNS application directly.'
  desc 'check', 'Verify that the core BIND 9.x server files are owned by the root or BIND 9.x process account.

With the assistance of the DNS administrator, identify the following files:

named.conf
root hints 
master zone file(s)
slave zone files(s)

Note: The name of the root hints file is defined in named.conf. Common names for the file are root.hints, named.cache, or db.cache.

If the identified files are not owned by the root or BIND 9.x process account, this is a finding.'
  desc 'fix', 'Change the ownership of the files to the root or BIND 9.x process account.

# chown <account_name> <file>'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7835r283794_chk'
  tag severity: 'medium'
  tag gid: 'V-207580'
  tag rid: 'SV-207580r612253_rule'
  tag stig_id: 'BIND-9X-001320'
  tag gtitle: 'SRG-APP-000516-DNS-000099'
  tag fix_id: 'F-7835r283795_fix'
  tag 'documentable'
  tag legacy: ['SV-87101', 'V-72477']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
