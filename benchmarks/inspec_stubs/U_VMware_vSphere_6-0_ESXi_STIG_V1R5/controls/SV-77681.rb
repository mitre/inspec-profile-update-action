control 'SV-77681' do
  title 'The SSH daemon must be configured to use only the SSHv2 protocol.'
  desc 'SSH protocol version 1 suffers from design flaws that result in security vulnerabilities and should not be used.'
  desc 'check', 'To verify which SSH protocol version is configured, run the following command: 

# grep -i "^Protocol" /etc/ssh/sshd_config

If there is no output or the output is not exactly "Protocol 2", this is a finding.'
  desc 'fix', 'Only SSH protocol version 2 connections should be permitted.

Add or correct the following line in "/etc/ssh/sshd_config":

Protocol 2'
  impact 0.7
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63925r1_chk'
  tag severity: 'high'
  tag gid: 'V-63191'
  tag rid: 'SV-77681r1_rule'
  tag stig_id: 'ESXI-06-000011'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag fix_id: 'F-69109r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
