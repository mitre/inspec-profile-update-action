control 'SV-217320' do
  title 'The Juniper router must be configured to be configured to prohibit the use of all unnecessary and nonsecure functions and services.'
  desc 'Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Review the services that have been enabled as shown in the following configuration example:
    services {
        finger;
        telnet;
        xnm-clear-text;
        netconf {
            ssh;
        }
    }

Services such as finger, telnet, and clear text-based JUNOScript connections should never be enabled. Other services such as Netconf, FTP, DHCP, and SSL-based JUNOScript connections should only be enabled if operationally required.

If the router is not configured to prohibit the use of all unnecessary and non-secure functions and services, this is a finding.'
  desc 'fix', 'Disable the following services if enabled as shown in the example below.

[edit system services]
delete telnet
delete finger
delete xnm-clear-text'
  impact 0.7
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18547r296538_chk'
  tag severity: 'high'
  tag gid: 'V-217320'
  tag rid: 'SV-217320r879588_rule'
  tag stig_id: 'JUNI-ND-000470'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-18545r296539_fix'
  tag 'documentable'
  tag legacy: ['SV-101225', 'V-91125']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
