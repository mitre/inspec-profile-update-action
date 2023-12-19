control 'SV-242185' do
  title 'In the event of a logging failure, caused by loss of communications with the central logging server, the SMS must queue audit records locally by using the syslog over TCP protocol until communication is restored or until the audit records are retrieved manually or using automated  synchronization tools.'
  desc 'It is critical that when the TPS is at risk of failing to process audit logs as required, it takes action to mitigate the failure.

Audit processing failures include: software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure.

The TPS performs a critical security function, so its continued operation is imperative. Since availability of the TPS is an overriding concern, shutting down the system in the event of an audit failure should be avoided except as a last resort. The SYSLOG protocol does not support automated synchronization; however, this functionality may be provided by Network Management Systems (NMSs) which are not within the scope of this STIG.'
  desc 'check', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Server Properties". 
2. Select the "syslog" tab. If each syslog setting is not configured with TCP as the protocol, this is a finding.'
  desc 'fix', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Server Properties". 
2. Select the "syslog" tab. 
3. Click "New". 
4. Under syslog server type the hostname or IP address of the syslog server. 
5. Click TCP to ensure logging data is queued in the case of disconnection of the syslog server. 
6. Type the port used by the centralized logging server (traditionally it is port 514). 
7. Under log type, select "Device Audit". 
8. Under facility click "Log Audit". 
9. Click Event timestamp under "Include Timestamp in Header". 
10. Select "include SMS hostname in header".
Repeat this three more times changing the Log Type to include Device System, SMS Audit, and SMS System.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45460r710096_chk'
  tag severity: 'medium'
  tag gid: 'V-242185'
  tag rid: 'SV-242185r710345_rule'
  tag stig_id: 'TIPP-IP-000190'
  tag gtitle: 'SRG-NET-000089-IDPS-00010'
  tag fix_id: 'F-45418r710097_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
