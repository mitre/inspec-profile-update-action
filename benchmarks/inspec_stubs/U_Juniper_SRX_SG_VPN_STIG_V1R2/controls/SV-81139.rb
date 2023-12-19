control 'SV-81139' do
  title 'The Juniper SRX Services Gateway VPN must be configured to use IPsec with SHA1 or greater to negotiate hashing to protect the integrity of remote access sessions.'
  desc 'Without strong cryptographic integrity protections, information can be altered by unauthorized users without detection. 

Remote access VPN provides access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.'
  desc 'check', 'Verify all IPSec proposals are set to use the sha-256 hashing algorithm.

[edit]
show security ipsec proposal <IPSEC-PROPOSAL-NAME>

View the value of the encryption algorithm for each defined proposal.

If the value of the encryption algorithm option for all defined proposals is not set to use SHA1 or greater, this is a finding.'
  desc 'fix', 'The following example commands configure the IPSec proposal.

set security ipsec proposal <IPSEC-PROPOSAL-NAME> authentication-algorithm <hmac-sha-256-128 | hmac-sha-256-96 | hmac-sha1-96>'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67275r2_chk'
  tag severity: 'medium'
  tag gid: 'V-66649'
  tag rid: 'SV-81139r2_rule'
  tag stig_id: 'JUSX-VN-000008'
  tag gtitle: 'SRG-NET-000063'
  tag fix_id: 'F-72725r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
