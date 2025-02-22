control 'SRG-NET-000100-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must protect session (call) records from unauthorized deletion.'
  desc 'If session records were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. To ensure the veracity of session records, the information system and/or the application must protect session information from unauthorized modification. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations.'
  desc 'check', 'Verify the Unified Communications Session Manager protects session records from unauthorized deletion.

If the Unified Communications Session Manager does not protect session records from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to protect session records from unauthorized deletion.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000100-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000100-VVSM-00101'
  tag rid: 'SRG-NET-000100-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000100-VVSM-00101'
  tag gtitle: 'SRG-NET-000100-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000100-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
