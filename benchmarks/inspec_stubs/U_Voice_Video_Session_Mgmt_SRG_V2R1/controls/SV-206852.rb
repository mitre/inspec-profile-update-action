control 'SV-206852' do
  title 'The Voice Video Session Manager must protect the integrity of transmitted configuration files, signaling, and media streams.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised as unprotected communications can be intercepted and either read or altered. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Voice Video protocol suites include SIP, SCCP, and H.323. Each of these protocol suites uses different methodologies for securing transmitted signaling. The H.323 protocol suite relies on the H.235 series, which describes security within H.323, including security for both signaling and media. For SIP protocol, the DoD has created the AS-SIP protocol, which provides for implementing Transport Layer Security (TLS), Multi-Level Precedence and Preemption (MLPP), reliance on Secure Real-Time Transport Protocol (SRTP) for media streams, and Differentiated Services Code Point (DSCP) for traffic management through priority packet routing. To secure SCCP, TLS must be implemented with the protocol.

Note: It is expected that this requirement be used to address each protocol individually. A separate STIG requirement for each protocol used identifying the methods to protect the confidentiality and integrity of transmitted control information (including registration files) and media streams must be produced.'
  desc 'check', 'Verify the Voice Video Session Manager protects the integrity of transmitted configuration files, signaling, and media streams.

If the Voice Video Session Manager does not protect the integrity of transmitted configuration files, signaling, and media streams, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to protect the integrity of transmitted configuration files, signaling, and media streams.'
  impact 0.7
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7107r364745_chk'
  tag severity: 'high'
  tag gid: 'V-206852'
  tag rid: 'SV-206852r508661_rule'
  tag stig_id: 'SRG-NET-000371-VVSM-00018'
  tag gtitle: 'SRG-NET-000371'
  tag fix_id: 'F-7107r364746_fix'
  tag 'documentable'
  tag legacy: ['SV-76625', 'V-62135']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
