control 'SV-221836' do
  title 'The Oracle Linux operating system must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.'
  desc "Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a denial of service.

If the system is intended to be a log aggregation server its use must be documented with the ISSO."
  desc 'check', 'Verify that the system is not accepting "rsyslog" messages from other systems unless it is documented as a log aggregation server.

Check the configuration of "rsyslog" with the following command:

# grep imtcp /etc/rsyslog.conf
$ModLoad imtcp
# grep imudp /etc/rsyslog.conf
$ModLoad imudp
# grep imrelp /etc/rsyslog.conf
$ModLoad imrelp

If any of the above modules are being loaded in the "/etc/rsyslog.conf" file, ask to see the documentation for the system being used for log aggregation.

If the documentation does not exist, or does not specify the server as a log aggregation system, this is a finding.'
  desc 'fix', 'Modify the "/etc/rsyslog.conf" file to remove the "ModLoad imtcp", "ModLoad imudp", and "ModLoad imrelp" configuration lines, or document the system as being used for log aggregation.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23551r419580_chk'
  tag severity: 'medium'
  tag gid: 'V-221836'
  tag rid: 'SV-221836r603260_rule'
  tag stig_id: 'OL07-00-031010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23540r419581_fix'
  tag 'documentable'
  tag legacy: ['SV-108515', 'V-99411']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
