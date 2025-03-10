control 'SV-55751' do
  title 'The A/B, A/B/C, or A/B/C/D switch used for network switching in IP-based VTC systems implementing a single CODEC supporting conferences on multiple networks having different classification levels must be Common Criteria certified.'
  desc 'Common Criteria provides assurance that the process of specification, implementation, and evaluation of a computer security product has been conducted in a rigorous, standard, and repeatable manner at a level that is commensurate with the target environment for use. The DSAWG mandated that the A/B, A/B/C, or A/B/C/D switches used in VTC systems implementing a single CODEC supporting conferences on multiple networks having different classification levels, where these networks are simultaneously and permanently connected to these networks, must receive NIAP approval in accordance with CNSSP #11. This was primarily due to the potential interconnection of separate networks designated as National Security Systems through the switch. This was a prerequisite to their approval of the multinetwork VTC system architecture.  Therefore, the A/B, A/B/C, or A/B/C/D switch must be satisfactorily evaluated and validated in accordance with the provisions of the NIAP Common Criteria Evaluation and Validation Scheme.'
  desc 'check', 'Review the NIAP Product Compliant List (PCL) at https://www.niap-ccevs.org to verify that a certification exists for the A/B, A/B/C, or A/B/C/D switch or review a vendor-provided letter from NIAP or the NIAP test report indicating satisfactory completion of testing and PCL listing. Validation of certification via the NIAP PCL can be more easily facilitated if the vendor has provided the certification number. If the product is not on the list or a NIAP letter or test report is not provided, this is a finding.'
  desc 'fix', 'Obtain and install an A/B, A/B/C, or A/B/C/D switch that has obtained Common Criteria certification.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49179r4_chk'
  tag severity: 'medium'
  tag gid: 'V-43022'
  tag rid: 'SV-55751r1_rule'
  tag stig_id: 'RTS-VTC 7140'
  tag gtitle: 'RTS-VTC 7140 [IP]'
  tag fix_id: 'F-48606r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCAS-1'
end
