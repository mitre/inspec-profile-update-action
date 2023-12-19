control 'SV-219557' do
  title 'The telnet daemon must not be running.'
  desc 'The telnet protocol uses unencrypted network communication, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network. The telnet protocol is also subject to man-in-the-middle attacks.

Mitigation:  If an enabled telnet daemon is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated.'
  desc 'check', 'To check that the "telnet" service is disabled in system boot configuration, run the following command: 

# chkconfig "telnet" --list

Output should indicate the "telnet" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "telnet" --list
telnet         off
OR
error reading information on service telnet: No such file or directory

If the service is running, this is a finding.'
  desc 'fix', 'The "telnet" service can be disabled with the following command: 

# chkconfig telnet off'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21282r462340_chk'
  tag severity: 'high'
  tag gid: 'V-219557'
  tag rid: 'SV-219557r603263_rule'
  tag stig_id: 'OL6-00-000211'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-21281r462341_fix'
  tag 'documentable'
  tag legacy: ['SV-64759', 'V-50553']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
