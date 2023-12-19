control 'SV-30031' do
  title 'A private web server must subscribe to certificates, issued from any DoD-authorized Certificate Authority, as an access control mechanism for web users.'
  desc "If the Hardware Management Consoles (HMC) is network-connected, use SSL encryption techniques, through digital certificates to provide message privacy, message integrity and mutual authentication between clients and servers. To maintain data integrity the IBM Certificate distributed with the HMC's is to be replaced by a DoD-authorized Certificate.  Note: This check applies only to network-connected HMCs."
  desc 'check', "The System Reviewer will have the System Administrator use the Hardware Management Console Certificate Management Task to validate that the private key and certificate shipped with any network-connected HMC from IBM was replaced with an approved DoD- authorized Certificate.

Note: This check applies only to network-connected HMCs.

Note: DoD certificates should display the following Information 'OU=PKI.OU=DoD.O=U.S. Government.C=US'

If  private web server does not subscribe to certificates issued from any DoD-authorized Certificate Authority as an access control mechanism for web users, then this is a FINDING."
  desc 'fix', 'The System Administrator must order a DoD PKI to replace the IBM Certificate and then  the System Administrator must use the Hardware Management Console Certificate Management Task to install it.

Note: This only applies to networked HMCs.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29866r2_chk'
  tag severity: 'medium'
  tag gid: 'V-24363'
  tag rid: 'SV-30031r3_rule'
  tag stig_id: 'HMC0170'
  tag gtitle: 'HMC0170'
  tag fix_id: 'F-26767r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'IATS-1, IATS-2'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
