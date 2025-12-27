control 'SV-45812' do
  title 'The hosts.lpd file (or equivalent) must not contain a + character.'
  desc "Having the '+' character in the hosts.lpd (or equivalent) file allows all hosts to use local system print resources."
  desc 'check', 'Look for the presence of a print service configuration file.

Procedure:
# find /etc -name hosts.lpd -print
# find /etc -name Systems -print  
# find /etc -name printers.conf

If none of the files are found, this check should be marked Not Applicable.  

Otherwise, examine the configuration file.

Procedure:
# more <print service file>

Check for entries that contain a ‘+’ or ‘_’ character.  If any are found, this is a finding.
For the "cups" print service, verify remote host access is limited.


# grep -i Listen /etc/cups/cupsd.conf 
The /etc/cups/cupsd.conf file must not contain a Listen *:<port> or equivalent line.
If the network address of the "Listen" line is unrestricted. This is a finding.

# grep -i "Allow From" /etc/cups/cupsd.conf 
The "Allow From" line within the "<Location />" element should limit access to the printers to @LOCAL and specific hosts.
If the "Allow From" line contains "All" this is a finding.'
  desc 'fix', %q(Remove the '+' entries from the hosts.lpd (or equivalent) file.

Configure cups to use only the localhost or specified remote hosts.

Procedure: 
Modify the /etc/cups/cupsd.conf file to "Listen" only to the local machine or a known set of hosts (i.e., Listen localhost:631).
Modify the /etc/cups/cupsd.conf file "<Location />" element to "Deny From All" and "Allow from 127.0.0.1" or allowed host addresses. 

Restart cups:
# rccups restart)
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-827'
  tag rid: 'SV-45812r1_rule'
  tag stig_id: 'GEN003900'
  tag gtitle: 'GEN003900'
  tag fix_id: 'F-39202r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
