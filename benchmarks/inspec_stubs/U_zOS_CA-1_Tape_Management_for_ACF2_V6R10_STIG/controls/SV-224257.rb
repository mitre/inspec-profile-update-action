control 'SV-224257' do
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
  ref 'DPMS Target zOS CA 1 Tape Management for ACF2'
  tag check_id: 'C-25930r519455_chk'
  tag severity: 'medium'
  tag gid: 'V-224257'
  tag rid: 'SV-224257r519457_rule'
  tag stig_id: 'ZCA10060'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25918r519456_fix'
  tag 'documentable'
  tag legacy: ['SV-40108', 'V-17985']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
