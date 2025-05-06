control 'SV-215385' do
  title 'The rquotad daemon must be disabled on AIX.'
  desc 'The rquotad service allows NFS clients to enforce disk quotas on file systems that are mounted on the local system. This service should be disabled if to prevent attacks.'
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^rquotad[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "rquotad" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'rquotad' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16583r294606_chk'
  tag severity: 'medium'
  tag gid: 'V-215385'
  tag rid: 'SV-215385r508663_rule'
  tag stig_id: 'AIX7-00-003080'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16581r294607_fix'
  tag 'documentable'
  tag legacy: ['V-91401', 'SV-101499']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
