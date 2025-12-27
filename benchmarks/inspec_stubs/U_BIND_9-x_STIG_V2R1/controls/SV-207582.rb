control 'SV-207582' do
  title 'The permissions assigned to the core BIND 9.x server files must be set to utilize the least privilege possible.'
  desc 'Discretionary Access Control (DAC) is based on the premise that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. In a DNS implementation, DAC should be granted to a minimal number of individuals and objects because DNS does not interact directly with users and users do not store and share data with the DNS application directly.'
  desc 'check', 'With the assistance of the DNS administrator, identify the following files:

named.conf : rw-r----- 
root hints : rw-r-----
master zone file(s): rw-r-----
slave zone file(s): rw-rw----

Note: The name of the root hints file is defined in named.conf. Common names for the file are root.hints, named.cache, or db.cache.

Verify that the permissions for the core BIND 9.x server files are at least as restrictive as listed above. 

If the identified files are not as least as restrictive as listed above, this is a finding.'
  desc 'fix', 'Configure the permissions of each file to the following:

named.conf : rw-r----- 
root hints : rw-r-----
master zone file(s): rw-r-----
slave zone file(s): rw-rw----'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7837r283800_chk'
  tag severity: 'medium'
  tag gid: 'V-207582'
  tag rid: 'SV-207582r612253_rule'
  tag stig_id: 'BIND-9X-001322'
  tag gtitle: 'SRG-APP-000516-DNS-000099'
  tag fix_id: 'F-7837r283801_fix'
  tag 'documentable'
  tag legacy: ['SV-87105', 'V-72481']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
