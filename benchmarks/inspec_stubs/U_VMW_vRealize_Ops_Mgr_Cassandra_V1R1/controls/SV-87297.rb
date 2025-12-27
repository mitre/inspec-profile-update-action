control 'SV-87297' do
  title 'The Cassandra Server must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', 'Review the Cassandra Server configuration to protect the confidentiality and integrity of all information at rest.

Inspect the server configuration to ensure a full disk encryption solution has been implemented.  If the disk is unencrypted, this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to protect the confidentiality and integrity of all information at rest.

Implement full disk encryption such as VMcrypt or other third-party full disk encryption that uses FIPS 140-2 validated cryptography.'
  impact 0.7
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72821r1_chk'
  tag severity: 'high'
  tag gid: 'V-72665'
  tag rid: 'SV-87297r1_rule'
  tag stig_id: 'VROM-CS-002065'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-79069r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
