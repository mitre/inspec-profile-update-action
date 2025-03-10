control 'SV-207565' do
  title 'The read and write access to a TSIG key file used by a BIND 9.x server must be restricted to only the account that runs the name server software.'
  desc 'Weak permissions of a TSIG key file could allow an adversary to modify the file, thus defeating the security objective.'
  desc 'check', 'Verify permissions assigned to the TSIG keys enforce read-write access to the key owner and deny access to group or system users:

With the assistance of the DNS Administrator, determine the location of the TSIG keys used by the BIND 9.x implementation:

# ls –al <TSIG_Key_Location>
-rw-------. 1 named named 76 May 10 20:35 tsig-example.key

If the key files are more permissive than 600, this is a finding.'
  desc 'fix', 'Change the permissions of the TSIG key files:

# chmod 600 <TSIG_key_file>'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7820r283749_chk'
  tag severity: 'medium'
  tag gid: 'V-207565'
  tag rid: 'SV-207565r612253_rule'
  tag stig_id: 'BIND-9X-001112'
  tag gtitle: 'SRG-APP-000176-DNS-000019'
  tag fix_id: 'F-7820r283750_fix'
  tag 'documentable'
  tag legacy: ['SV-87065', 'V-72441']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
