control 'SV-255284' do
  title 'The HPE 3PAR OS must be configured to offload audit records onto a different system or media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

'
  desc 'check', 'Verify offloading of security syslog events with 

cli% showsys -d

Find the output section "Remote Syslog Status".

If "Active" is not "1", this is a finding.

If "Security Server" is not defined, this is a finding.

If "Security Connection" is not "TLS", this is a finding.'
  desc 'fix', 'Configure the remote syslog host:

cli% setsys RemoteSyslogSecurityHost <hostname> <address-spec> [:port]

The hostname, and address are both required. If both IPv4 and IPv6 addresses are supplied, the IPv6 address must be enclosed in []. The default port is 6514 utilizing TLS.

Import the ca certificate that will have signed the syslog server:

cli% importcert syslog-sec-server -ca stdin

Copy and paste the PEM format of the appropriate CA as instructed.

Configure the system to utilize remote syslog:

cli% setsys RemoteSyslog 1'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58957r870169_chk'
  tag severity: 'medium'
  tag gid: 'V-255284'
  tag rid: 'SV-255284r870171_rule'
  tag stig_id: 'HP3P-33-002052'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-58901r870170_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
