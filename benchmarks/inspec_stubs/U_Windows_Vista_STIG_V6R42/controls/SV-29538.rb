control 'SV-29538' do
  title 'The system is configured to use an unauthorized time server.'
  desc 'The Windows Time Service controls time synchronization settings.  Time synchronization is essential for authentication and auditing purposes.  If the Windows Time Service is used, it should synchronize with a secure, authorized time source.   Domain joined systems are automatically configured to synchronize with domain controllers.  If an NTP server is configured it should synchronize with a secure, authorized time source.'
  desc 'check', 'Review the following registry values:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\W32time\\Parameters\\

Value Name: Type
Type: REG_SZ
Value: Possible values are NoSync, NTP, NT5DS, AllSync

And

Value Name: NTPServer
Type: REG_SZ
Value: "address of the time server"

The following would be a finding:
"Type" has a value of "NTP" or "Allsync" AND the "NTPServer" value is set to "time.windows.com" or other unauthorized server.

The following would not be a finding:
The referenced registry values do not exist.
"Type" has a value of "NoSync" or "NT5DS".
"Type" has a value of "NTP" or "Allsync" AND the "NTPServer" is blank or configured to an authorized time server.

For DoD organizations, the US Naval Observatory operates stratum 1 time servers, identified at http://tycho.usno.navy.mil/ntp.html. Time synchronization will occur through a hierarchy of time servers down to the local level. Clients and lower level servers will synchronize with an authorized time server in the hierarchy. 

Domain joined systems are automatically configured to synchronize with domain controllers and would not be a finding unless this is changed. 

Automated tools may report this as finding even if enabled and configured correctly as the validity of the time server address needs to be verified.'
  desc 'fix', 'If the system needs to be configured to an NTP server, configure the system to point to an authorized time server by setting the policy value for Computer Configuration -> Administrative Templates -> System -> Windows Time Service -> Time Providers “Configure Windows NTP Client” to “Enabled”, and configure the “NtpServer” field to point to an authorized time server.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-39220r1_chk'
  tag severity: 'low'
  tag gid: 'V-3472'
  tag rid: 'SV-29538r1_rule'
  tag gtitle: 'Windows Time Service - Configure NTP Client'
  tag fix_id: 'F-34317r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
