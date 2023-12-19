control 'SV-81685' do
  title 'The Arista Multilayer Switch must be updated to one of the minimum approved versions of EOS.'
  desc 'The Arista Multilayer Switch uses the EOS operating system. Updates to EOS contain new security-related features and security patches that address known vulnerabilities. Running a current DoD-approved software version improves the security posture of the network device.'
  desc 'check', 'Verify the Arista Multilayer Switch configuration using the “Show version” command. Review the software image version, and verify it is a minimum DoD-approved version. The current approved minimum versions are 4.16.0F, 4.15.3F, 4.14.11M, or later. If the Arista Multilayer Switch is not using a minimum approved versions of EOS, this is a finding.'
  desc 'fix', 'Configure the Arista Multilayer Switch to use an approved software version. Download the approved version from www.arista.com/support, copy the .swi file to flash via an approved file transfer mechanism, and then enter:

Enable
Configure
Boot system flash:<your_image.swi>
Write memory
reload'
  impact 0.3
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-67773r1_chk'
  tag severity: 'low'
  tag gid: 'V-67195'
  tag rid: 'SV-81685r1_rule'
  tag stig_id: 'AMLS-NM-000500'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-73307r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
