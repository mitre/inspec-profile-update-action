control 'SV-82971' do
  title 'The Mainframe Product must implement security safeguards to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Examine installation and configuration settings.

Determine if critical core programs to the operating system are identified.

If the Mainframe Product does not protect critical core programs, this is a finding.

If an external security manager (ESM) is in use verify that the ESM is configured and/or has rules to protect critical core programs. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to identify critical core programs to the operating system for protection in accordance with applicable access control policies.

This can be accomplished by an external security manager (ESM). Configure the ESM to restrict access to these critical core programs to appropriate users in accordance with applicable access control policies.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69013r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68481'
  tag rid: 'SV-82971r1_rule'
  tag stig_id: 'SRG-APP-000450-MFP-000338'
  tag gtitle: 'SRG-APP-000450-MFP-000338'
  tag fix_id: 'F-74597r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
