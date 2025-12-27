control 'SV-90903' do
  title 'CounterACT must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this certification authority will suffice.'
  desc 'check', 'Determine if CounterACT obtains public key certificates from an appropriate certificate policy through an approved service provider.

1. Open a command line SSH to CounterACT appliance or Enterprise Manager.
2. Run the following command:
>fstool dot1x cert print <pathname/filename> for the local server certificate (/usr/local/forescout/etc/dot1x/certs.production/server.pem)
3. Verify the signing authority is from an approved certificate authority.

If the network device does not obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding.'
  desc 'fix', 'Configure CounterACT to obtain its public key certificates from an appropriate certificate policy through an approved service provider.

Reference CounterACT 802.1x Plugin guide/help manual under Certificate Request process for additional details on the signing process.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75901r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76215'
  tag rid: 'SV-90903r1_rule'
  tag stig_id: 'CACT-NM-000016'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-82851r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
