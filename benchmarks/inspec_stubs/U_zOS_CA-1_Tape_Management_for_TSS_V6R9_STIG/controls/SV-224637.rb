control 'SV-224637' do
  title 'CA 1 Tape Management user exits, when in use, must be reviewed and/or approved.'
  desc 'CA-1 Tape Management user exits, TMSUXnA and TMSUXnS, provide the capability to bypass or modify existing ACP controls.  A review and evaluation of exit code must be performed to ensure that the integrity of the CA-1 processing environment is kept intact.  Unauthorized usage of these exits may compromise the confidentiality and integrity of customer data.'
  desc 'check', 'Refer to the following report produced by the z/OS Data Collection:

-       CA1RPT(TMSCKLVL)

Determine if CA 1 user exits, TMSUXnA and TMSUXnS (for r11.5 and below) or TMSXITA and TMSXITS (for r12.0 and above) are active.

If both CA 1 user exits are not found, this is not a finding.

If one or both user exits are installed and the following requirements are true, this is not a finding:

___       The usage and function of the user exit(s) is fully documented.
___       The use of the user exit(s) is approved.
___       All associated documentation is on file with the ISSO.'
  desc 'fix', 'Ensure that the site ISSO has reviewed, evaluated, and approved the usage of CA 1 user exits, TMSUXnA and TMSUXnS (for r11.5 and below) or TMSXITA and TMSXITS (for r12.0 and above). If one or both user exits are installed and the following requirements will be followed:

The usage and function of the user exit(s) is fully documented.

The use of the user exit(s) is approved.

All associated documentation is on file with the ISSO.'
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for TSS'
  tag check_id: 'C-26320r519515_chk'
  tag severity: 'medium'
  tag gid: 'V-224637'
  tag rid: 'SV-224637r519517_rule'
  tag stig_id: 'ZCA10060'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26308r519516_fix'
  tag 'documentable'
  tag legacy: ['V-17985', 'SV-40108']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
