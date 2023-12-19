control 'SV-207563' do
  title 'The TSIG keys used with the BIND 9.x implementation must be owned by a privileged account.'
  desc 'Incorrect ownership of a TSIG key file could allow an adversary to modify the file, thus defeating the security objective.'
  desc 'check', 'With the assistance of the DNS Administrator, identify all of the TSIG keys used by the BIND 9.x implementation.

Identify the account that the "named" process is running as:

# ps -ef | grep named
named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

With the assistance of the DNS Administrator, determine the location of the TSIG keys used by the BIND 9.x implementation.

# ls –al <TSIG_Key_Location>
-rw-------. 1 named named 76 May 10 20:35 tsig-example.key

If any of the TSIG keys are not owned by the above account, this is a finding.'
  desc 'fix', 'Change the ownership of the TSIG keys to the named process is running as.

# chown <named_proccess_owner> <TSIG_key_file>.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7818r283743_chk'
  tag severity: 'medium'
  tag gid: 'V-207563'
  tag rid: 'SV-207563r612253_rule'
  tag stig_id: 'BIND-9X-001110'
  tag gtitle: 'SRG-APP-000176-DNS-000018'
  tag fix_id: 'F-7818r283744_fix'
  tag 'documentable'
  tag legacy: ['SV-87061', 'V-72437']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
