control 'SV-52335' do
  title 'The system must disable accounts after three consecutive unsuccessful SSH login attempts.'
  desc 'Disabling accounts after a limited number of unsuccessful SSH login attempts improves protection against password guessing attacks.'
  desc 'check', "If the system is operating in Trusted Mode, this check is not applicable.

For SMSE:
The “UsePAM” attribute in the /opt/ssh/etc/sshd_config configuration file controls whether an account is locked after too many consecutive SSH authentication failures. The default “UsePAM” attribute setting is “no”. Verify the global setting for “UsePAM” is set to “yes”.
# cat /opt/ssh/etc/sshd_config | sed -e 's/^[ \\t]*//' grep -v “#” | grep “^UsePAM”

If the /opt/ssh/etc/sshd_config configuration file attribute “UsePAM” is not set to “yes”, this is a finding."
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE only:
Edit the /opt/ssh/etc/sshd_config file and add/uncomment/update the “UsePAM” attribute. See the below example:
UsePAM yes

Save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-46984r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40355'
  tag rid: 'SV-52335r1_rule'
  tag stig_id: 'GEN000000-HPUX0210'
  tag gtitle: 'GEN000000-HPUX0210'
  tag fix_id: 'F-45323r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLO-2, ECLO-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
