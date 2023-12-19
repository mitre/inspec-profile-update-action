control 'SV-55745' do
  title 'An IP-based VTC system implementing a single CODEC supporting conferences on multiple networks having different classification levels (i.e., unclassified, SECRET, TOP SECRET, TS-SCI) must support Periods Processing by connecting the CODEC to one network at a time, matching the classification level of the session to the classification level of the network.'
  desc 'Connecting to networks of different classifications simultaneously incurs the risk of data from a higher classification being released to a network of a lower classification, referred to as a “spill”. It is imperative that networks of differing classification levels or with differing handling caveats not be interconnected at any time. Separation in a multinetwork VTC system is maintained by the use of an A/B, A/B/C, or A/B/C/D switch that meets requirements for channel isolation, or by manual connection of the CODEC to one network at a time.'
  desc 'check', 'Review the VTC system architecture to verify that an approved A/B, A/B/C, or A/B/C/D switch is present and properly cabled. Alternately, validate that the VTC CODEC is manually connected to one network at a time through the use of a single patch cord. If neither is in place, this is a finding.'
  desc 'fix', 'Obtain and install an approved A/B, A/B/C, or A/B/C/D switch. Alternately, manually connect the VTC CODEC to one network at a time through the use of a single patch cord.'
  impact 0.7
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49173r4_chk'
  tag severity: 'high'
  tag gid: 'V-43016'
  tag rid: 'SV-55745r1_rule'
  tag stig_id: 'RTS-VTC 7020'
  tag gtitle: 'RTS-VTC 7020 [IP]'
  tag fix_id: 'F-48600r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'EBCR-1, ECIC-1'
end
