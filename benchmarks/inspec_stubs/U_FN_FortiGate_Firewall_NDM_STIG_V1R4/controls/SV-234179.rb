control 'SV-234179' do
  title 'The FortiGate device must generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. 

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment within which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     #  show full-configuration system global | grep -i cli-audit
The output should be:   
          set cli-audit-log enable

If cli-audit-log is set to disable, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
   # config system global
   #      set cli-audit-log enable
   # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37364r611724_chk'
  tag severity: 'medium'
  tag gid: 'V-234179'
  tag rid: 'SV-234179r879569_rule'
  tag stig_id: 'FGFW-ND-000100'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-37329r611725_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
