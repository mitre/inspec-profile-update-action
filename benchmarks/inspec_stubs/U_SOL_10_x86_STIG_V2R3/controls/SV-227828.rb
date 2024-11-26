control 'SV-227828' do
  title 'The hosts.lpd file (or equivalent) must not contain a "+" character.'
  desc 'Having the "+" character in the hosts.lpd (or equivalent) file allows all hosts to use local system print resources.'
  desc 'check', 'Solaris uses the "IPP" print service and can also use the Samba print service. Verify remote host access is limited.

Procedure:
# grep -i Listen /etc/apache/httpd-standalone-ipp.conf
The /etc/apache/httpd-standalone-ipp.conf file must not contain a Listen *:<port> or equivalent line.
If the network address of the "Listen" line is unrestricted, this is a finding.

# grep -i "Allow From" /etc/apache/httpd-standalone-ipp.conf
The "Allow From" line within the "<Location />" element should limit access to the printers to @LOCAL and specific hosts.
If the "Allow From" line contains "All", this is a finding. 

Verify guest access to printers shared via Samba is restricted according to GEN006235.'
  desc 'fix', 'Configure IPP to use only the localhost or specified remote hosts.

Procedure:
Modify the /etc/apache/httpd-standalone-ipp.conf file to "Listen" only to the local machine or a known set of hosts (i.e., Listen localhost:631).
Modify the /etc/apache/httpd-standalone-ipp.conf file "<Location />" element to "Deny From All" and "Allow from 127.0.0.1" or allowed host addresses.

Restart the IPP service:
# svcadm restart ipp-listener'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36470r603013_chk'
  tag severity: 'medium'
  tag gid: 'V-227828'
  tag rid: 'SV-227828r603266_rule'
  tag stig_id: 'GEN003900'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36434r603014_fix'
  tag 'documentable'
  tag legacy: ['V-827', 'SV-40457']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
