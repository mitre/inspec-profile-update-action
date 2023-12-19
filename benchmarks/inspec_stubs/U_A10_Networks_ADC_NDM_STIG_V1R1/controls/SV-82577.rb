control 'SV-82577' do
  title 'Operators of the A10 Networks ADC must not use the Telnet client built into the device.'
  desc 'If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to manipulation, potentially allowing alteration and hijacking of maintenance sessions. Telnet is an unsecure protocol; use SSH instead. 

Note: This requirement does not refer to the device accepting incoming Telnet connections (server), but instead being used as an originator of Telnet requests (client). This is the exec level command "telnet".'
  desc 'check', 'Determine if any operators have used Telnet. Evidence of the use of Telnet will be in the audit log.

The following command shows any instances of the word "telnet" in the audit log:
show audit | inc telnet

If the log shows the use of the Telnet command, this is a finding.'
  desc 'fix', 'The device has a Telnet client that is available at the privileged exec level. Do not use it; use SSH from a management workstation instead.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68647r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68087'
  tag rid: 'SV-82577r1_rule'
  tag stig_id: 'AADC-NM-000118'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-74201r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
