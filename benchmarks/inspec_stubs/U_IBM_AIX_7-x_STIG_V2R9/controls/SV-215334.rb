control 'SV-215334' do
  title 'AIX must disable trivial file transfer protocol.'
  desc 'Without auditing the enforcement of access restrictions against changes to the application configuration, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^tftp[[:blank:]]" /etc/inetd.conf

If there is any output from the command, it is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "tftp" entry: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'tftp' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16532r294453_chk'
  tag severity: 'high'
  tag gid: 'V-215334'
  tag rid: 'SV-215334r853483_rule'
  tag stig_id: 'AIX7-00-003022'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-16530r294454_fix'
  tag 'documentable'
  tag legacy: ['SV-101629', 'V-91531']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
