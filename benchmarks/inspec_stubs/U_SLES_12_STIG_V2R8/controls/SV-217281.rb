control 'SV-217281' do
  title 'The SUSE operating system clock must, for networked systems, be synchronized to an authoritative DoD time source at least every 24 hours.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

'
  desc 'check', 'Verify the SUSE operating system clock must be configured to synchronize to an authoritative DoD time source when the time difference is greater than one second. 

Check that the SUSE operating system clock must be configured to synchronize to an authoritative DoD time source when the time difference is greater than one second with the following command:

> sudo grep maxpoll /etc/ntp.conf

server 0.us.pool.ntp.mil maxpoll 16

If nothing is returned or "maxpoll" is greater than "16", or is commented out, this is a finding.

Verify the "ntp.conf" file is configured to an authoritative DoD time source by running the following command:

> sudo grep -i server /etc/ntp.conf
server 0.us.pool.ntp.mil 

If the parameter "server" is not set or is not set to an authoritative DoD time source, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system clock must be configured to synchronize to an authoritative DoD time source when the time difference is greater than one second. 

To configure the system clock to synchronize to an authoritative DoD time source at least every 24 hours, edit the file "/etc/ntp.conf". Add or correct the following lines by replacing "[time_source]" with an authoritative DoD time source:

server [time_source] maxpoll 16'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18509r646754_chk'
  tag severity: 'medium'
  tag gid: 'V-217281'
  tag rid: 'SV-217281r854159_rule'
  tag stig_id: 'SLES-12-030300'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-18507r370000_fix'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144']
  tag 'documentable'
  tag legacy: ['V-77475', 'SV-92171']
  tag cci: ['CCI-002046', 'CCI-001891']
  tag nist: ['AU-8 (1) (b)', 'AU-8 (1) (a)']
end
