control 'SV-26968' do
  title 'The system must have USB disabled unless needed.'
  desc 'USB is a common computer peripheral interface.  USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'fix', 'Remove the SUNWusb package.
# pkgrm SUNWusb'
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-22578'
  tag rid: 'SV-26968r1_rule'
  tag stig_id: 'GEN008460'
  tag gtitle: 'GEN008460'
  tag fix_id: 'F-24230r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
