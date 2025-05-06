control 'SV-218521' do
  title 'The hosts.lpd file (or equivalent) must not contain a + character.'
  desc "Having the '+' character in the hosts.lpd (or equivalent) file allows all hosts to use local system print resources."
  desc 'check', 'The operating system uses the CUPS print service.  Verify remote host access is limited.

Procedure:
# grep -i Listen /etc/cups/cupsd.conf
 
The /etc/cups/cupsd.conf file must not contain a Listen *:<port> or equivalent line.

If the network address of the "Listen" line is unrestricted, this is a finding.

# grep -i "Allow From" /etc/cups/cupsd.conf
 
The "Allow From" line within the "<Location />" element should limit access to the printers to @LOCAL and specific hosts.
If the "Allow From" line contains "All" this is a finding.'
  desc 'fix', 'Configure cups to use only the localhost or specified remote hosts.

Procedure: 
Modify the /etc/cups/cupsd.conf file to "Listen" only to the local machine or a known set of hosts (i.e., Listen localhost:631).
Modify the /etc/cups/cupsd.conf file "<Location />" element to "Deny From All" and "Allow from 127.0.0.1" or allowed host addresses. 

Restart cups:
# service cups restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19996r555761_chk'
  tag severity: 'medium'
  tag gid: 'V-218521'
  tag rid: 'SV-218521r603259_rule'
  tag stig_id: 'GEN003900'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19994r555762_fix'
  tag 'documentable'
  tag legacy: ['V-827', 'SV-64115']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
