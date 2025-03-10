control 'SV-95595' do
  title 'AAA Services must be configured to authenticate all NTP messages received from NTP servers and peers.'
  desc %q(Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. NTP provides an efficient and scalable method for network devices to synchronize to an accurate time source. NTP may pose a security risk if a malicious user were able to falsify NTP information. To launch an attack on the NTP infrastructure, a hacker could inject time that would be accepted by NTP clients by spoofing the IP address of a valid NTP server. To mitigate this risk, the time messages must be authenticated by the client before accepting them as a time source. 

Two NTP-enabled devices can communicate in either client-server mode or peer-to-peer mode (aka "symmetric mode"). The peering mode is configured manually on the device and indicated in the outgoing NTP packets. The fundamental difference is the synchronization behavior: an NTP server can synchronize to a peer with better stratum, whereas it will never synchronize to its client regardless of the client's stratum. From a protocol perspective, NTP clients are no different from the NTP servers. The NTP client can synchronize to multiple NTP servers, select the best server and synchronize with it, or synchronize to the averaged value returned by the servers.

A hierarchical model can be used to improve scalability. With this implementation, an NTP client can also become an NTP server providing time to downstream clients at a higher stratum level and of decreasing accuracy than that of its upstream server. To increase availability, NTP peering can be used between NTP servers. In the event the device loses connectivity to its upstream NTP server, it will be able to choose time from one of its peers. 

The NTP authentication model is opposite of the typical client-server authentication model. NTP authentication enables an NTP client or peer to authenticate time received from their servers and peers. It is not used to authenticate NTP clients because NTP servers do not care about the authenticity of their clients, as they never accept any time from them.)
  desc 'check', 'Verify AAA Services are configured to authenticate all NTP messages received from NTP servers and peers. 

The NTP server or peer authentication must use a FIPS-approved message authentication code algorithm. FIPS-approved algorithms for authentication are the cipher-based message authentication code (CMAC) and the keyed-hash message authentication code (HMAC). AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256. AAA Services may leverage the capability of an operating system.

If AAA Services are not configured to authenticate all NTP messages using a FIPS-approved message authentication code algorithm, this is a finding.

If AAA Services are not capable of authenticating the NTP server or peer using a FIPS-approved message authentication code algorithm, but are configured to use an MD5 for NTP message authentication, this is downgraded to a CAT III.'
  desc 'fix', 'Configure AAA Services to authenticate all received NTP messages using a FIPS-approved message authentication code algorithm. When AAA Services are not capable of using FIPS-approved message authentication code algorithms, configure AAA Services to use MD5 message authentication code algorithms.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80623r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80885'
  tag rid: 'SV-95595r1_rule'
  tag stig_id: 'SRG-APP-000516-AAA-000360'
  tag gtitle: 'SRG-APP-000516-AAA-000360'
  tag fix_id: 'F-87741r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001891']
  tag nist: ['CM-6 b', 'AU-8 (1) (a)']
end
