control 'SV-217317' do
  title 'The Juniper router must be configured to protect audit information from unauthorized modification.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit network device activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the network device must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The configuration example below allows only users belonging to the AUDITOR class to configure the logging parameters.

system {
    login {
        class AUDITOR {
            permissions [configure view-configuration];
            allow-configuration "(system syslog)";
        }
        class SR_ENGINEER {
            permissions all;
            deny-configuration "(system syslog)";
        }
    }
}

If the router is not configured to protect audit information from unauthorized modification, this is a finding.'
  desc 'fix', 'Create a login class that provides the permission to configure logging parameters as well as a classes that do not allow configuration of logging parameters as shown in the example below.

[edit system]
set login class AUDITOR permissions [configure view-configuration]
set login class AUDITOR allow-configuration "(system syslog)"

set login class SR_ENGINEER permissions all 
set login class SR_ENGINEER deny-configuration "(system syslog)"'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18544r296529_chk'
  tag severity: 'medium'
  tag gid: 'V-217317'
  tag rid: 'SV-217317r879577_rule'
  tag stig_id: 'JUNI-ND-000380'
  tag gtitle: 'SRG-APP-000119-NDM-000236'
  tag fix_id: 'F-18542r296530_fix'
  tag 'documentable'
  tag legacy: ['SV-101219', 'V-91119']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
