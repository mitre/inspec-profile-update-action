control 'SV-207581' do
  title 'The core BIND 9.x server files must be group owned by a group designated for DNS administration only.'
  desc 'Discretionary Access Control (DAC) is based on the premise that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. In a DNS implementation, DAC should be granted to a minimal number of individuals and objects because DNS does not interact directly with users and users do not store and share data with the DNS application directly.'
  desc 'check', 'Verify that the core BIND 9.x server files are group owned by a group designated for DNS administration only.

With the assistance of the DNS administrator, identify the following files:

named.conf
root hints 
master zone file(s)
slave zone file(s)

Note: The name of the root hints file is defined in named.conf. Common names for the file are root.hints, named.cache, or db.cache.

If the identified files are not group owned by a group designated for DNS administration, this is a finding.'
  desc 'fix', 'Change the ownership of the core BIND 9.x server files to the process account group.

# chgrp (BIND 9.x process account) <file>'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7836r283797_chk'
  tag severity: 'medium'
  tag gid: 'V-207581'
  tag rid: 'SV-207581r612253_rule'
  tag stig_id: 'BIND-9X-001321'
  tag gtitle: 'SRG-APP-000516-DNS-000099'
  tag fix_id: 'F-7836r283798_fix'
  tag 'documentable'
  tag legacy: ['SV-87103', 'V-72479']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
