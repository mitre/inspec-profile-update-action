control 'SV-102397' do
  title 'The SEL-2740S must be configured to establish trust relationships with parent OTSDN Controller(s).'
  desc 'Machine to machine initial trust must be established between the OTSDN controller and the SEL-2740S for authenticating all communications and configuration thereafter.  Certificates must be created and safely stored.  Backup OTSDN controller trust should also be established and locked down.  Any time that these need to be modified the SEL-2740S must be factory default reset and adoption process must be re-executed.'
  desc 'check', 'Ensure the SEL-2740S is adopted by only the appropriate OTSDN Controller(s) by checking the "Topology" page on the OTSDN Controller for the SEL-2740S under test to ensure it is adopted by the appropriate OTSDN Controller(s).

If the SEL-2740S is adopted by a rogue OTSDN Controller or does not appear as an adopted device in the network, this is a finding.'
  desc 'fix', 'To configure the SEL-2740S for initial trust and X.509 certificate creation for TLS communications, the device needs to be adopted by OTSDN controller.
Before adopting, create an SEL-2740S configuration node object. 

To adopt an SEL-2740S do the following:
1. Go to the "Topology" page.
2. Select on the SEL-2740S you want to adopt. The "Option" window shows the SEL-2740S "Node Options" pane.
3. Select the SEL-2740S configuration node from the "Configuration" setting. The "Adopt Configuration" button is enabled.
4. Click the "Adopt Configuration" button. The "Feedback" bar displays "Success" to indicate successful application of the configuration node. The adoption process starts.
5. Wait until the alarm contact pulses (about 30 to 60 seconds). After clicking the "Adopt" button, the process may take a minute or longer to complete depending on the speed of the SEL-5056 host machine. When complete, the selected object becomes adopted, the appropriate ports appear, and the Adoption State is "Adopted".'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91605r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92309'
  tag rid: 'SV-102397r1_rule'
  tag stig_id: 'SELS-ND-001420'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-98547r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
