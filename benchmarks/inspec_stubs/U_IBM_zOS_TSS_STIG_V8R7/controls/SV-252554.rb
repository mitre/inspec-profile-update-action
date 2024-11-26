control 'SV-252554' do
  title 'IBM z/OS TCP/IP AT-TLS policy must be properly configured in Policy Agent.'
  desc 'If events associated with nonlocal administrative access or diagnostic sessions are not logged, a major tool for assessing and investigating attacks would not be available.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

Nonlocal maintenance and diagnostic activities are conducted by individuals communicating through an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system; for example, the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch.'
  desc 'check', 'Use the z/OS UNIX pasearch -t command to query information from the z/OS UNIX Policy Agent. 

The command is issued from the UNIX System Services shell.

Examine the results for AT-TLS initiation and control statements.

If there are no AT-TLS initiation and controls statements, this is a finding.

Verify the statements specify a FIPS 140-2 compliant value. If none of the following values are present, this is a finding

ECDHE_ECDSA_AES_128_CBC_SHA256
ECDHE_ECDSA_AES_256_CBC_SHA384
ECDHE_RSA_AES_128_CBC_SHA256
ECDHE_RSA_AES_256_CBC_SHA384
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA256'
  desc 'fix', 'Develop a plan of action to implement the required changes. Ensure the following items are in effect for TCP/IP resources.

Develop AT-TLS policy. Install in the policy agent.

Ensure the statements specify a FIPS 140-2 compliant value of the following values.

ECDHE_ECDSA_AES_128_CBC_SHA256
ECDHE_ECDSA_AES_256_CBC_SHA384
ECDHE_RSA_AES_128_CBC_SHA256
ECDHE_RSA_AES_256_CBC_SHA384
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA256'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-56010r816960_chk'
  tag severity: 'medium'
  tag gid: 'V-252554'
  tag rid: 'SV-252554r816962_rule'
  tag stig_id: 'TSS0-TC-000100'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-55960r816961_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
