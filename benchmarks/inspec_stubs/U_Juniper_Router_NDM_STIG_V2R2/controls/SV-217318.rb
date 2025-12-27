control 'SV-217318' do
  title 'The Juniper router must be configured to protect audit information from unauthorized deletion.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the network device must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order to make access decisions regarding the deletion of audit data.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The configuration example below depicts a class "JR_ENGINEER" which does not permit users belonging to the class to delete files or make changes to logging parameters.

login {
       class JR_ENGINEER {
            permissions all;
            deny-commands "(file delete)";
            deny-configuration "(system syslog)";
        }
}

Note: The predefined classes "Operator" and "Read-only" do not have permissions to delete files.

If the router is not configured to protect audit information from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure one or more classes as shown in the example below whose users will not be permitted to delete files or make changes to logging parameters.

[edit system]
set login class JR_ENGINEER permissions all 
set login class JR_ENGINEER deny-configuration "(system syslog)"
set login class JR_ENGINEER deny-commands “(file delete)”'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18545r296532_chk'
  tag severity: 'medium'
  tag gid: 'V-217318'
  tag rid: 'SV-217318r395826_rule'
  tag stig_id: 'JUNI-ND-000390'
  tag gtitle: 'SRG-APP-000120-NDM-000237'
  tag fix_id: 'F-18543r296533_fix'
  tag 'documentable'
  tag legacy: ['SV-101221', 'V-91121']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
