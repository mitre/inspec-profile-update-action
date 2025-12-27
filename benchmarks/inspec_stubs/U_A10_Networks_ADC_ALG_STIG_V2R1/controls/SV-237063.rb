control 'SV-237063' do
  title 'The A10 Networks ADC must protect against TCP SYN floods by using TCP SYN Cookies.'
  desc 'A SYN flood is a form of denial-of-service attack in which an attacker sends a succession of SYN requests to a target in an attempt to consume resources, making the device unresponsive to legitimate traffic. TCP SYN Cookies are commonly implemented by the Operating System on endpoints, but are also often implemented on network devices.

A10 Networks ADCs provide protection against TCP SYN flood attacks by using SYN cookies. SYN cookies enable the device to continue to serve legitimate clients during a TCP SYN flood attack without allowing illegitimate traffic to consume system resources.'
  desc 'check', 'Review the device configuration.

The following command displays the device configuration and filters the output on the string "syn-cookie":

show run | inc syn-cookie

If SYN cookies are not enabled, this is a finding.'
  desc 'fix', 'The following command enables hardware-based SYN cookies:
syn-cookie on-threshold [num] off-threshold [num]

Note: Hardware-based SYN cookies are available only on some models. If the "on-threshold" and "off-threshold" options are omitted, SYN cookies are enabled and are always on regardless of the number of half-open TCP connections.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40282r639634_chk'
  tag severity: 'medium'
  tag gid: 'V-237063'
  tag rid: 'SV-237063r639636_rule'
  tag stig_id: 'AADC-AG-000156'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-40245r639635_fix'
  tag 'documentable'
  tag legacy: ['SV-82517', 'V-68027']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
