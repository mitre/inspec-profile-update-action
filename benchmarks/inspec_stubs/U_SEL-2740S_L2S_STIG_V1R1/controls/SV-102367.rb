control 'SV-102367' do
  title 'The SEL-2740S must be configured to capture all packets without flow rule match criteria.'
  desc 'The OTSDN switch must be capable of capturing frames that are not engineered to be in the network and send them to a Security Information and Event Manager (SIEM) or midpoint sensor for analysis.'
  desc 'check', 'Review the SEL-2740S to ensure that the "no match criteria" rule is set to capture the packet for analysis as a possible injection or intrusion. 

If the SEL-2740S is not configured to with the "no match criteria" rules for the Security Information and Event Manager (SIEM), this is a finding.'
  desc 'fix', 'To configure to capture all packets without flow rule match criteria, do the following:
1. Log on to OTSDN Controller using Permission Level 3.
2. Click "Flow Entries" in Navigation Menu.
3. Click "Add Flow" button.
4. Enter a "no match" flow rule for given ports.
5. Click "Submit".'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91577r3_chk'
  tag severity: 'medium'
  tag gid: 'V-92279'
  tag rid: 'SV-102367r1_rule'
  tag stig_id: 'SELS-SW-000290'
  tag gtitle: 'SRG-NET-000512-L2S-000029'
  tag fix_id: 'F-98519r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
