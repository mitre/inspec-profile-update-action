control 'SV-90901' do
  title 'CounterACT must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this certification authority will suffice.'
  desc 'check', 'Determine if CounterACT obtains public key certificates from an appropriate certificate policy through an approved service provider.

To review the Web server certificate presented for captive portal/authentication:

1. Open a command line SSH to CounterACT appliance or Enterprise Manager.
2. Run the following command:
>fstool cert test
3. Verify all Web server certificate(s) are printed and reviewable.
4. Verify the signing authority is from an approved certificate authority.

If the network device does not obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding.'
  desc 'fix', 'Configure CounterACT to obtain its public key certificates from an appropriate certificate policy through an approved service provider.

Reference CounterACT Admin Manual and Appendix 1: Command line tools and subsection "Generating CSRs and importing signed certificates" for more detail on requesting a signed certificate.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76213'
  tag rid: 'SV-90901r1_rule'
  tag stig_id: 'CACT-NM-000015'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-82849r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
